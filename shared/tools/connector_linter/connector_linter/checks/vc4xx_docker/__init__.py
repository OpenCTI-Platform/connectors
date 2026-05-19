"""VC4xx — Docker checks.

Validates Docker configuration (Dockerfile, docker-compose.yml) for
compliance with OpenCTI verified-connector conventions.

VC401  docker-compose-image       Image must use :latest tag and match directory name
VC402  no-entrypoint-sh           Dockerfile must not use entrypoint.sh
"""
