package org.logstash.settings;

import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;


/**
 * A <code>SettingWithDeprecatedAlias</code> wraps any <code>Setting</code> to provide a deprecated
 * alias, and hooks @see org.logstash.settings.Setting#validate_value() to ensure that a deprecation
 * warning is fired when the setting is provided by its deprecated alias,
 * or to produce an error when both the canonical name and deprecated
 * alias are used together.
 * */
class SettingWithDeprecatedAlias<T> extends SettingDelegator<T> {
    
    /**
     * Wraps the provided setting, returning a pair of connected settings
     * including the canonical setting and a deprecated alias.
     * @param canonicalSetting the setting to wrap
     * @param deprecatedAliasName the name for the deprecated alias
     *
     * @return List of [SettingWithDeprecatedAlias, DeprecatedAlias]
     * */
    static <T> List<Setting<T>> wrap(Setting<T> canonicalSetting, String deprecatedAliasName) {
        final SettingWithDeprecatedAlias<T> settingProxy = new SettingWithDeprecatedAlias<>(canonicalSetting, deprecatedAliasName);
        return Arrays.asList(settingProxy, settingProxy.deprecatedAlias);
    }

    private DeprecatedAlias<T> deprecatedAlias;

    protected SettingWithDeprecatedAlias(String name, T defaultValue, boolean strict, Predicate<T> validator) {
        super(name, defaultValue, strict, validator);
    }

    protected SettingWithDeprecatedAlias(Setting<T> canonicalSetting, String deprecatedAliasName) {
        super(canonicalSetting);

        this.deprecatedAlias = new DeprecatedAlias<T>(this, deprecatedAliasName);
    }

    Setting<T> getCanonicalSetting() {
        return getDelegate();
    }

    @Override
    public void set(T value) {
        getCanonicalSetting().set(value);
    }

    @Override
    public T value() {
        if (getCanonicalSetting().isSet()) {
            return super.value();
        }
        // bypass warning by querying the wrapped setting's value
        if (deprecatedAlias.isSet()) {
            return deprecatedAlias.getDelegate().value();
        }
        return getDefault();
    }

    @Override
    public boolean isSet() {
        return getCanonicalSetting().isSet() || deprecatedAlias.isSet();
    }

    @Override
    public void format(List<String> output) {
        if (!(deprecatedAlias.isSet() && !getCanonicalSetting().isSet())) {
            super.format(output);
            return;
        }
        output.add(String.format("*%s: %s (via deprecated `%s`; default: %s)",
                getName(), value(), deprecatedAlias.getName(), getDefault()));
    }
}