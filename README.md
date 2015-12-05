# Luzifer / fitbit\_exporter

This project is intended to be a connector between the FitBit API and a self-hosted Prometheus instance. The exporter registers for push events in FitBit API and exposes metrics towards Prometheus.

**Attention:** This project is currently WIP and does NOT have the intended isolation of data between users! This is currently not possible because the Go library for Prometheus does not support this but it will be possible in the future as this is something being worked on by the Prometheus team.
