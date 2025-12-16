package org.logstash.instrument.metrics;

import co.elastic.logstash.api.UserMetric;

import java.util.Map;

public interface HistogramFlowMetric extends UserMetric<Map<String, HistogramMetricData>>,
        org.logstash.instrument.metrics.Metric<Map<String, HistogramMetricData>> {

    Provider<HistogramFlowMetric> PROVIDER = new Provider<>(HistogramFlowMetric.class, new HistogramFlowMetric() {
        @Override
        public Map<String, HistogramMetricData> getValue() {
            return Map.of();
        }

        @Override
        public String getName() {
            return "NULL";
        }

        @Override
        public void recordValue(long totalByteSize) {
            // no-op
        }
    });

    void recordValue(long totalByteSize);

    @Override
    default MetricType getType() {
        return MetricType.USER;
    }
}
