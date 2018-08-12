
MAPL (Manageable Access-control Policy Language) is a

# Manageable Access-control Policy Language

# MAPL engine

# Status of the MAPL Project
This project is still under active development, so you might run into issues. If you do, please don't be shy about letting us know, or better yet, contribute a fix or feature.
If you have any questions about MAPL or how to use the MAPL engine, please contact...

# Engine Roadmap
- Currently the engine supports service to service communication. We need to support ingress and egress by IP or CIDR
- Support Istio's source.labels and destination.labels
- Suppert HTTP request headers
- Add patterns to the wildcard use (*,?) similar to fnmatch [https://www.gnu.org/software/libc/manual/html_node/Wildcard-Matching.html]? Or allow input of regex in rules?
