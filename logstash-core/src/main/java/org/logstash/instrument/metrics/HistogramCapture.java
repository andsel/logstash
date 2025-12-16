package org.logstash.instrument.metrics;

import org.HdrHistogram.Histogram;

public class HistogramCapture implements DatapointCapture {
    private final Histogram hdrHistogram;
    private final long nanoTime;

    public HistogramCapture(Histogram histogram, long nanoTime) {
        this.hdrHistogram = histogram;
        this.nanoTime = nanoTime;
    }

    public Histogram getHdrHistogram() {
        return hdrHistogram;
    }

    @Override
    public long nanoTime() {
        return nanoTime;
    }
}
