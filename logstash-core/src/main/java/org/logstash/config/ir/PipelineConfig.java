package org.logstash.config.ir;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jruby.*;
import org.logstash.common.IncompleteSourceWithMetadataException;
import org.logstash.common.SourceWithMetadata;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static org.logstash.RubyUtil.RUBY;

public final class PipelineConfig {

    private static class LineToSource {
        private final int startLine;
        private final int endLine;
        private final SourceWithMetadata source;

        LineToSource(int startLine, int endLine, SourceWithMetadata source) {
            this.startLine = startLine;
            this.endLine = endLine;
            this.source = source;
        }

        boolean includeLine(int lineNumber) {
            return startLine <= lineNumber && lineNumber <= endLine;
        }
    }

    private static final Logger logger = LogManager.getLogger(PipelineConfig.class);

    private RubyClass source;
    private String pipelineId;
    private List<SourceWithMetadata> confParts;
    private RubyObject settings;
    private LocalDateTime readAt;
    private String configHash;
    private String configString;
    private List<LineToSource> sourceRefs;

    @SuppressWarnings({"rawtypes", "unchecked"})
    public PipelineConfig(RubyClass source, RubySymbol pipelineId, RubyObject uncastedConfigParts, RubyObject logstashSettings) {
        RubyArray configParts;
        if (!uncastedConfigParts.checkArrayType().isNil()) {
            configParts = uncastedConfigParts.convertToArray();
        } else {
            configParts = RubyArray.newArray(RUBY, uncastedConfigParts);
        }

        this.source = source;
        this.pipelineId = pipelineId.toString();
        SourceWithMetadata[] castedConfigParts = (SourceWithMetadata[]) configParts.toJava(SourceWithMetadata[].class);
        List<SourceWithMetadata> confParts = Arrays.asList(castedConfigParts);
        confParts.sort(Comparator.comparing(SourceWithMetadata::getProtocol)
                .thenComparing(SourceWithMetadata::getId));
        this.confParts = confParts;
        this.settings = logstashSettings;
        this.readAt = LocalDateTime.now();
    }

    public RubyClass getSource() {
        return source;
    }

    public String getPipelineId() {
        return pipelineId;
    }

    public List<SourceWithMetadata> getConfigParts() {
        return confParts;
    }

    public LocalDateTime getReadAt() {
        return readAt;
    }

    public RubyObject getSettings() {
        return settings;
    }

    public String configHash() {
        if (configHash == null) {
            configHash = DigestUtils.sha1Hex(configString());
        }
        return configHash;
    }

    public String configString() {
        this.configString = confParts.stream().map(SourceWithMetadata::getText).collect(Collectors.joining("\n"));
        return this.configString;
    }

    public boolean isSystem() {
        return this.settings.callMethod(RUBY.getCurrentContext(), "get_value",
                                        RubyString.newString(RUBY, "pipeline.system"))
                .toJava(Boolean.class);
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }
        if (!(other instanceof PipelineConfig)) {
            return false;
        }
        PipelineConfig cother = (PipelineConfig) other;
        return configHash().equals(cother.configHash()) &&
                this.pipelineId.equals(cother.pipelineId) &&
                this.settings.callMethod(RUBY.getCurrentContext(), "==", cother.settings).toJava(Boolean.class);
    }

    @Override
    public int hashCode() {
        return this.configHash().hashCode();
    }

    public void displayDebugInformation() {
        logger.debug("-------- Logstash Config ---------");
        logger.debug("Config from source, source: {}, pipeline_id:: {}", source, pipelineId);

        for (SourceWithMetadata configPart : this.confParts) {
            logger.debug("Config string, protocol: {}, id: {}", configPart.getProtocol(), configPart.getId());
            logger.debug("\n\n{}", configPart.getText());
        }
        logger.debug("Merged config");
        logger.debug("\n\n{}", this.configString());
    }

    public SourceWithMetadata lookupSource(int globalLineNumber, int sourceColumn)
            throws IncompleteSourceWithMetadataException {
        LineToSource lts = this.sourceReferences().stream()
                .filter(lts1 -> lts1.includeLine(globalLineNumber))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("can't find the config segment related to line " + globalLineNumber));
        return new SourceWithMetadata(lts.source.getProtocol(), lts.source.getId(),
                globalLineNumber + 1 - lts.startLine, sourceColumn, lts.source.getText());
    }

    private List<LineToSource> sourceReferences() {
        if (this.sourceRefs == null) {
            int offset = 0;
            List<LineToSource> sourceRefs = new ArrayList<>();

            for (SourceWithMetadata configPart : confParts) {
                //line numbers starts from 1 in text files
                int startLine = configPart.getLine() + offset + 1;
                int endLine = configPart.getLinesCount() + offset;
                LineToSource sourceSegment = new LineToSource(startLine, endLine, configPart);
                sourceRefs.add(sourceSegment);
                offset += configPart.getLinesCount();
            }
            this.sourceRefs = Collections.unmodifiableList(sourceRefs);
        }
        return this.sourceRefs;
    }

}
