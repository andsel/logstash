package org.logstash.instrument.metrics;

import co.elastic.logstash.api.UserMetric;
import org.HdrHistogram.Histogram;
import org.HdrHistogram.Recorder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public class HdrHistogramFlowMetric extends AbstractMetric<Map<String, HistogramMetricData>> implements HistogramFlowMetric {

    private static final Logger LOG = LogManager.getLogger(HdrHistogramFlowMetric.class);

    public static UserMetric.Factory<HistogramFlowMetric> FACTORY = HistogramFlowMetric.PROVIDER.getFactory(HdrHistogramFlowMetric::new);

    //TODO should have same infrastructure code as ExtendedFlowMetric to capture rates over time.
    FlowMetricRetentionPolicy retentionPolicy = FlowMetricRetentionPolicy.BuiltInRetentionPolicy.LAST_1_MINUTE;
    ExtendedFlowMetric.RetentionWindow recordWindowLastMinute;
    private AtomicLong lastRecordTimeNanos;

    private final Recorder histogramRecorder;

    /**
     * Constructor
     *
     * @param name The name of this metric. This value may be used for display purposes.
     */
    protected HdrHistogramFlowMetric(String name) {
        super(name);
        histogramRecorder = new Recorder(1_000_000, 3);
        long actualTime = System.nanoTime();
        lastRecordTimeNanos = new AtomicLong(actualTime);
        HistogramCapture initialCapture = new HistogramCapture(histogramRecorder.getIntervalHistogram(), actualTime);
        recordWindowLastMinute = new ExtendedFlowMetric.RetentionWindow(retentionPolicy, initialCapture);
    }

    @Override
    public Map<String, HistogramMetricData> getValue() {
        final Histogram windowAggregated = new Histogram(1_000_000, 3);
        recordWindowLastMinute.forEachCapture(dpc -> {
            if (dpc instanceof HistogramCapture hdp) {
                windowAggregated.add(hdp.getHdrHistogram());
            } else {
                LOG.warn("Found {} which is not a HistogramCapture in HdrHistogramFlowMetric retention window",
                        dpc.getClass().getName());
            }
        });

        return Map.of("last_1_minute", new HistogramMetricData(windowAggregated));
    }

    @Override
    public void recordValue(long totalByteSize) {
        histogramRecorder.recordValue(totalByteSize);

        // Record on every call and create a snapshot iff we pass the flow metric policy resolution time
        long currentTimeNanos = System.nanoTime();
        long updatedLast = lastRecordTimeNanos.accumulateAndGet(currentTimeNanos, (last, current) -> {
            if (current - last > retentionPolicy.resolutionNanos()) {
                return current;
            } else {
                return last;
            }
        });
        //TODO possible problem if thread suspend here, time passes, and another thread updates lastRecordTimeNanos?
        if (updatedLast == currentTimeNanos) {
            // an update of the lastRecordTimeNanos happened, we need to create a snapshot
            Histogram snaspshotHistogram = histogramRecorder.getIntervalHistogram();
            recordWindowLastMinute.append(new HistogramCapture(snaspshotHistogram, currentTimeNanos));
        }
    }
}
