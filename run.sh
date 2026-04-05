#!/bin/bash
# SentinelAI — Quick Start Script
# Usage: ./run.sh [dev|docker|test]

set -e

MODE=${1:-dev}
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗${NC}"
  echo -e "${CYAN}  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║${NC}"
  echo -e "${CYAN}  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║${NC}"
  echo -e "${CYAN}  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║${NC}"
  echo -e "${CYAN}  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║${NC}"
  echo -e "${CYAN}  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝${NC}"
  echo ""
  echo -e "${GREEN}  AI-Driven Threat Detection & Simulation Engine${NC}"
  echo -e "${YELLOW}  Hack Malenadu '26 | Cybersecurity Track | Problem Statement 3${NC}"
  echo ""
}

check_prereqs() {
  if [ "$MODE" = "docker" ]; then
    command -v docker >/dev/null 2>&1 || { echo -e "${RED}Docker not found. Install Docker first.${NC}"; exit 1; }
    command -v docker-compose >/dev/null 2>&1 || { echo -e "${RED}docker-compose not found.${NC}"; exit 1; }
  else
    command -v python3 >/dev/null 2>&1 || { echo -e "${RED}Python 3 not found.${NC}"; exit 1; }
    command -v node >/dev/null 2>&1    || { echo -e "${RED}Node.js not found.${NC}"; exit 1; }
  fi
}

run_tests() {
  echo -e "${CYAN}Running detection engine tests...${NC}"
  python3 -c "
import sys
sys.path.insert(0, 'backend')
from log_generator import BruteForceAttack, C2BeaconAttack, DataExfilAttack, benign_network_event
from detection_engine import DetectionEngine
import time

engine = DetectionEngine()
# Train
for _ in range(40):
    engine.process(benign_network_event())
assert engine._trained, 'Forest not trained'

# Test brute force
bf = BruteForceAttack()
bf_alerts = []
for i in range(80):
    a = engine.process(bf.next_event())
    if a: bf_alerts.append(a)
assert len(bf_alerts) > 0, 'Brute force not detected'
print(f'  ✓ Brute force: {bf_alerts[0].severity} ({bf_alerts[0].confidence:.0%})')

# Test data exfil
ex = DataExfilAttack()
ex_alerts = []
for i in range(5):
    for evt in ex.next_event():
        a = engine.process(evt)
        if a: ex_alerts.append(a)
assert len(ex_alerts) > 0, 'Data exfil not detected'
print(f'  ✓ Data exfil: {ex_alerts[0].severity} ({ex_alerts[0].confidence:.0%})')

print('')
print('All detection tests passed ✓')
"
  echo ""
}

start_dev() {
  banner
  check_prereqs

  if [ "${1}" = "test" ]; then
    run_tests
    exit 0
  fi

  echo -e "${GREEN}Starting backend...${NC}"
  cd backend
  pip install -r requirements.txt -q 2>/dev/null || true
  uvicorn main:app --host 0.0.0.0 --port 8000 &
  BACKEND_PID=$!
  cd ..

  sleep 2
  echo -e "${GREEN}Starting frontend...${NC}"
  cd frontend
  npm install --silent 2>/dev/null || true
  npm run dev &
  FRONTEND_PID=$!
  cd ..

  echo ""
  echo -e "${GREEN}✓ SentinelAI is running!${NC}"
  echo ""
  echo -e "  Dashboard:  ${CYAN}http://localhost:3000${NC}"
  echo -e "  API docs:   ${CYAN}http://localhost:8000/docs${NC}"
  echo -e "  API health: ${CYAN}http://localhost:8000/api/health${NC}"
  echo ""
  echo -e "${YELLOW}Press Ctrl+C to stop${NC}"

  trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Stopped.'" EXIT
  wait
}

start_docker() {
  banner
  check_prereqs
  echo -e "${GREEN}Building and starting with Docker...${NC}"
  docker-compose up --build
}

case "$MODE" in
  docker) start_docker ;;
  test)   run_tests ;;
  dev|*)  start_dev ;;
esac
