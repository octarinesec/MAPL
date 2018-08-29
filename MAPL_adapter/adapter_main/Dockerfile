FROM ubuntu:17.10
ADD MAPL_adapter /
ADD run_MAPL_adapter.sh /

# for production:
CMD ["/MAPL_adapter","7782","/etc/rules/rules.yaml"]
#  for debugging:
# CMD ["/run_MAPL_adapter.sh","7782","/etc/rules/rules.yaml"]
