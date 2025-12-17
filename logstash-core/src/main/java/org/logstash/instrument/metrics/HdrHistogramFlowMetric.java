package org.logstash.instrument.metrics;

import co.elastic.logstash.api.UserMetric;
import org.HdrHistogram.Histogram;
import org.HdrHistogram.Recorder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

public class HdrHistogramFlowMetric extends AbstractMetric<Map<String, HistogramMetricData>> implements HistogramFlowMetric {

    /**
     * Support class to hold a window of histogram snapshots and histogram recorder.
     * */
    private static final class HistogramSnapshotsWindow {
        private final FlowMetricRetentionPolicy retentionPolicy;
        private final Recorder histogramRecorder;
        private final AtomicLong lastRecordTimeNanos;
        ExtendedFlowMetric.RetentionWindow recordWindow;

        HistogramSnapshotsWindow(FlowMetricRetentionPolicy retentionPolicy) {
            this.retentionPolicy = retentionPolicy;
            this.histogramRecorder = new Recorder(1_000_000, 3);
            long actualTime = System.nanoTime();
            lastRecordTimeNanos = new AtomicLong(actualTime);
            HistogramCapture initialCapture = new HistogramCapture(histogramRecorder.getIntervalHistogram(), actualTime);
            recordWindow = new ExtendedFlowMetric.RetentionWindow(retentionPolicy, initialCapture);
        }

        void recordValue(long totalByteSize) {
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
                recordWindow.append(new HistogramCapture(snaspshotHistogram, currentTimeNanos));
            }
        }

        HistogramMetricData computeAggregatedHistogramData() {
            final Histogram windowAggregated = new Histogram(1_000_000, 3);
            final long currentTimeNanos = System.nanoTime();
            recordWindow.forEachCapture(dpc -> {
                if ((currentTimeNanos - dpc.nanoTime()) > retentionPolicy.retentionNanos()) {
                    // skip captures outside of retention window
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("Skipping capture outside of retention window {}, expired {} seconds ago",
                                retentionPolicy.policyName(),
                                Duration.ofNanos((currentTimeNanos - dpc.nanoTime()) - retentionPolicy.retentionNanos())
                                /*((currentTimeNanos - dpc.nanoTime()) - retentionPolicy.retentionNanos()) / 1_000_000_000*/);
                    }
                    return;
                }

                if (dpc instanceof HistogramCapture hdp) {
                    windowAggregated.add(hdp.getHdrHistogram());
                } else {
                    LOG.warn("Found {} which is not a HistogramCapture in HdrHistogramFlowMetric retention window",
                            dpc.getClass().getName());
                }
            });
            LOG.info("Aggregate estimated size: {}", recordWindow.countCaptures());
            return new HistogramMetricData(windowAggregated);
        }
    }

    private static final Logger LOG = LogManager.getLogger(HdrHistogramFlowMetric.class);

    public static UserMetric.Factory<HistogramFlowMetric> FACTORY = HistogramFlowMetric.PROVIDER.getFactory(HdrHistogramFlowMetric::new);

    //TODO should have same infrastructure code as ExtendedFlowMetric to capture rates over time.
//    FlowMetricRetentionPolicy retentionPolicy = FlowMetricRetentionPolicy.BuiltInRetentionPolicy.LAST_1_MINUTE;

    private static final List<FlowMetricRetentionPolicy> SUPPORTED_POLICIES = List.of(
            FlowMetricRetentionPolicy.BuiltInRetentionPolicy.LAST_1_MINUTE/*,
            FlowMetricRetentionPolicy.BuiltInRetentionPolicy.LAST_5_MINUTES,
            FlowMetricRetentionPolicy.BuiltInRetentionPolicy.LAST_15_MINUTES*/
    );
//    private final HistogramSnapshotsWindow histogramSnapshotsWindow = new HistogramSnapshotsWindow(retentionPolicy);
    private final ConcurrentMap<FlowMetricRetentionPolicy, HistogramSnapshotsWindow> histogramsWindows = new ConcurrentHashMap<>();

    /**
     * Constructor
     *
     * @param name The name of this metric. This value may be used for display purposes.
     */
    protected HdrHistogramFlowMetric(String name) {
        super(name);
        for (FlowMetricRetentionPolicy policy : SUPPORTED_POLICIES) {
            histogramsWindows.put(policy, new HistogramSnapshotsWindow(policy));
        }
    }

    @Override
    public Map<String, HistogramMetricData> getValue() {
        final Map<String, HistogramMetricData> result = new HashMap<>();
        final long currentTimeNanos = System.nanoTime();
        histogramsWindows.forEach((policy, window) -> {
            window.recordWindow.baseline(currentTimeNanos).ifPresent(baseline -> {
                LOG.info("getValue computing aggregated histogram");
                result.put(policy.policyName().toLowerCase(), window.computeAggregatedHistogramData());
            });
        });
        return result;
    }

    @Override
    public void recordValue(long totalByteSize) {
        for (FlowMetricRetentionPolicy policy : SUPPORTED_POLICIES) {
            histogramsWindows.get(policy).recordValue(totalByteSize);
        }
//        histogramSnapshotsWindow.recordValue(totalByteSize);
    }
}
