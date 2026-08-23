#!/bin/bash
# Validação completa do solver CapMonster na stack Firecrawl.
# Roda este script no diretório ~/.services/firecrawl-custom/ na VM 1.
# Saída esperada em "RESUMO FINAL" no final.
set +e

cd ~/.services/firecrawl-custom 2>/dev/null || {
  echo "ERRO: rode em ~/.services/firecrawl-custom/"
  exit 1
}

API="http://localhost:3002"
TIMEOUT=45

probe_env() {
  echo "=== [1/4] Env vars CapMonster no container playwright ==="
  docker exec firecrawl-playwright-service-1 sh -c '
    echo "CAPMONSTER_ENABLED=[$CAPMONSTER_ENABLED]"
    echo "CAPMONSTER_API_KEY_LEN=[${#CAPMONSTER_API_KEY}]"
    echo "CAPMONSTER_TIMEOUT_MS=[$CAPMONSTER_TIMEOUT_MS]"
    echo "CAPMONSTER_POLL_INTERVAL_MS=[$CAPMONSTER_POLL_INTERVAL_MS]"
  '
  echo ""
}

probe_patch() {
  echo "=== [2/4] Patch compilado no /app/dist/ ==="
  HITS=$(docker exec firecrawl-playwright-service-1 sh -c '
    grep -rl "capmonster\|solveCaptchaIfPresent" /app/dist/ 2>/dev/null
  ')
  if [ -z "$HITS" ]; then
    echo "FALHA: patch NAO encontrado no /app/dist/"
    echo "       Imagem precisa rebuildar com git pull + build --no-cache"
  else
    echo "OK: arquivos com patch:"
    echo "$HITS" | head -5
  fi
  echo ""
}

probe_direct_solver() {
  echo "=== [3/4] Teste direto da API CapMonster do container playwright ==="
  echo "(confirma que a key CapMonster no .env funciona pra cobrar)"
  docker exec firecrawl-playwright-service-1 sh -c '
    KEY="$CAPMONSTER_API_KEY"
    if [ -z "$KEY" ]; then
      echo "FALHA: CAPMONSTER_API_KEY vazia no container"
      exit 0
    fi
    echo "key prefix: ${KEY:0:6}..."
    echo "balance ANTES:"
    curl -sS -m 8 -X POST https://api.capmonster.cloud/getBalance \
      -H "Content-Type: application/json" \
      -d "{\"clientKey\":\"$KEY\"}"
    echo ""
  '
  echo ""
}

probe_logs_during_scrape() {
  echo "=== [4/4] Logs do container DURANTE scrape com Turnstile real ==="
  echo "(democaptcha Turnstile sitekey 0x4AAAAAAARPza_BWW3rhRhj)"
  echo ""
  # Limpa log pra ver só esse scrape
  docker logs --tail=1 firecrawl-playwright-service-1 > /dev/null 2>&1
  docker logs -f firecrawl-playwright-service-1 2>&1 > /tmp/fc-solver.log &
  LOGPID=$!
  sleep 1
  echo "scrape democaptcha..."
  curl -sS -m $TIMEOUT -X POST $API/v2/scrape \
    -H 'Content-Type: application/json' \
    -d '{"url":"https://democaptcha.com/demo-form-eng/turnstile.html","formats":["markdown"]}' \
    > /tmp/fc-scrape-resp.json
  sleep 2
  kill $LOGPID 2>/dev/null
  wait 2>/dev/null
  echo "--- LOGS (filtrado por solver/captcha) ---"
  if [ -s /tmp/fc-solver.log ]; then
    grep -iE "capmonster|captcha|solveCaptcha|error" /tmp/fc-solver.log | head -20
    LINES=$(wc -l < /tmp/fc-solver.log)
    echo "(total $LINES linhas no log; filtro reduziu pra cima)"
  else
    echo "VAZIO: container nao emitiu nenhum log durante o scrape"
    echo "       Sintoma de: solver NAO esta sendo invocado"
  fi
  echo ""
  echo "--- SCRAPE RESPONSE ---"
  head -c 300 /tmp/fc-scrape-resp.json
  echo ""
}

echo "================================================================"
echo "  Firecrawl x CapMonster — diagnóstico"
echo "================================================================"
echo ""

probe_env
probe_patch
probe_direct_solver
probe_logs_during_scrape

echo "================================================================"
echo "  RESUMO FINAL"
echo "================================================================"
echo "Se [1] mostra key_len > 20 e enabled=true: ENV OK"
echo "Se [2] lista arquivos: PATCH OK"
echo "Se [3] retorna balance numero (sem errorCode): KEY CAPMONSTER VALIDA"
echo "Se [4] mostra logs 'capmonster' ou 'solveCaptcha': SOLVER SENDO INVOCADO"
echo ""
echo "Cole a saida inteira deste script na conversa para diagnóstico."
