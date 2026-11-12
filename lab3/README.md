# Lab 3 – Ex3: Orchestrator-Workers

Rulare (din `lab3/`):

```bash
python lab3_ex3_orchestrator.py single --auto-approve
python lab3_ex3_orchestrator.py orchestrator --auto-approve
python lab3_ex3_orchestrator.py subagent --auto-approve
```

## Tabelul cu tokeni

| mode | orchestrator input tokens per step | orchestrator total | worker total | grand total |
|---|---|---|---|---|
| single | [296, 58501, 59394] | 118,191 | 0 | 118,191 |
| orchestrator | [316, 693, 1358] | 2,367 | 58,235 | 60,602 |
| subagent | [327, 706, 1063] | 2,096 | 7,341 | 9,437 |

## Întrebarea 4: de ce scade și totalul general?

În modul `single`, cei ~58k tokeni ai logului intră în istoricul orchestratorului, iar API-ul e stateless, deci tot istoricul se retrimite la fiecare pas. Logul e plătit de două ori (pasul 2 și pasul 3), adică ~118k tokeni. În modul `orchestrator`, worker-ul citește logul o singură dată, într-un context separat, și returnează doar un JSON compact. Orchestratorul retrimite la fiecare pas doar acel JSON de câteva sute de tokeni, nu logul. Așa că logul e plătit o dată (~58k), iar totalul aproape se înjumătățește. Diferența crește cu fiecare pas în plus al orchestratorului.

## Homework: sub-agent

În modul `subagent`, worker-ul e un agent ReAct (`run_agent`) care nu citește tot fișierul. Folosește doar `grep_log`, `count_by_ip` și `context_around`, apoi concluziile lui sunt transformate în același `TriageReport`. Dacă sub-agentul se oprește fără să termine, `delegate_log_triage_agent` întoarce `ERROR`, iar orchestratorul refuză să scrie raportul. Asta s-a întâmplat la o rulare în care sub-agentul a atins `max_steps`: orchestratorul a răspuns că triajul a eșuat și nu a scris nimic.

### Cât de des are dreptate?

5 rulări ale sub-agentului, comparate cu ce e plantat în log (compromis, CRITICAL, IP `198.51.100.77`, userul `svc-backup` cu UID 0, descărcarea `x.sh`, regulă de firewall pentru atacator):

| rulare | tokeni worker | corect | ce a ratat |
|---|---|---|---|
| 1 | 24,757 | da | – |
| 2 | 29,161 | nu | userul backdoor `svc-backup` |
| 3 | 17,804 | nu | userul backdoor `svc-backup` |
| 4 | 7,085 | nu | tot: a raportat LOW, necompromis, fără IP |
| 5 | 19,340 | nu | `svc-backup` și descărcarea `x.sh` |

Rezultat: **1/5 corecte**. Sub-agentul e mult mai ieftin (7k–29k tokeni față de 58k), dar ratează des pași din lanțul de atac, pentru că vede doar ce caută. Cel mai grav e cazul 4: raportul e greșit, dar arată la fel de sigur ca unul corect. Exact asta s-a întâmplat la rularea din tabelul de tokeni, unde orchestratorul a scris un raport cu „minor brute-force activity”. E problema de „summary bottleneck”: orchestratorul știe doar ce îi raportează worker-ul.

### Cum verifici ieftin ce spune worker-ul?

- **Dovezile trebuie să existe exact în log.** Fiecare linie din `evidence` se caută verbatim în fișier, cu cod, fără LLM. Asta prinde dovezile inventate.
- **Faptele cheie se verifică determinist.** IP-urile din `attacker_ips` trebuie să aibă o linie `Accepted` în log. `is_compromised=true` trebuie să vină cu o linie `Accepted password` în dovezi.
- **Omisiunile se prind cu căutări fixe.** Câteva `grep`-uri ieftine pentru semnele critice (`Accepted password` de la IP-uri externe, `useradd ... UID=0`, `curl`/`wget` rulat ca root) se compară cu raportul. Dacă grep găsește ceva ce raportul nu menționează, raportul e respins sau trimis înapoi la worker. Verificarea verbatim singură nu ajunge: în cele 5 rulări a semnalat doar una dintre cele 4 greșite, pentru că problema principală au fost omisiunile, nu dovezile inventate.
- **Regulile de firewall se verifică înainte de folosire.** Trebuie să fie comenzi simple `ufw`/`iptables`, care conțin doar IP-ul atacatorului. Sunt date nesigure, nu se rulează direct.
