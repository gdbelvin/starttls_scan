#!/usr/bin/env python
import sys,string,os, subprocess, select
import random
import time
from subprocess import PIPE

lines = open("top-1m.csv").readlines()

hostlegal = ".-" + string.ascii_letters + string.digits

THREADS=128
MAX_CNAME_LOOP = 10

DOMAINS_TO_CHECK = 5000

queries = {}
selectors = []

def rns():
  return random.choice(["8.8.8.8", "4.2.2.2"])

def fetch_top_mx_records():
  invalid = 0
  results = []
  t0 = time.time()
  for l in lines:
    try:
      number, entry = l.strip().split(",")
      if int(number) > DOMAINS_TO_CHECK: break
    except:
      print "argh", l
      invalid +=1
      continue
    host = entry.partition("/")[0]
    if any([c not in hostlegal for c in host]):
      invalid += 1
      break
    else:
        results.append(host)
        #print "querying", number, host
        cmd = subprocess.Popen(['host', '-t', 'mx', host], stdout=PIPE)
        cmd.loopcount = MAX_CNAME_LOOP
        cmd.host = host
        cmd.orighost = host
        cmd.type = "mx"
        cmd.callback = process_mx_response
        selectors.append(cmd.stdout)
        queries[cmd.stdout] = cmd
        
        if len(selectors) >= THREADS:
            ready, _w, _e = select.select(selectors,[],[])
            for r in ready:
              cmd = queries[r]
              out, err = cmd.communicate()
              cmd.callback(cmd,out,err)
              selectors.remove(r)
              del queries[r]
  t1 = time.time()
  sys.stderr.write("Checked %d domains in %.3f seconds\n" % (DOMAINS_TO_CHECK, t1 - t0))

def dns_sanity_check(cmd, out, err):
  if "NXDOMAIN" in out:
    #sys.stderr.write("Invalid domain " + cmd.host + "\n")
    return False
  if "has no MX record" in out:
    #sys.stderr.write("No mx entry for " + cmd.host + "\n")
    return False
  if "connection timed out; no servers could be reached" in out:
    sys.stderr.write("Timeout for " + cmd.host + "\n")
    return False
  if "SERVFAIL" in out:
    sys.stderr.write("SERVFAIL for " + cmd.host + "\n")
    return False
  return True
    
def process_mx_response(cmd, out, err):

  if not dns_sanity_check(cmd,out, err): return False

  for line in out.split("\n"):
    l = line.strip()
    if not l: continue
    
    if "Truncated, retrying in TCP mode." in l:
      continue

    if " is an alias for " in l:
      return lookup_alias(l, cmd)

    if "mail is handled by" not in l:
      sys.stderr.write("weird line\n" + l+ "\n")
    else:
      domain, _m, rest = l.partition(" mail is handled by ")
      if domain != cmd.host:
        sys.stderr.write("Weird MX entry for %s->%s\n%s\n" % (cmd.orighost, cmd.host, l))
        continue
      priority, server = rest.split()
      # We have a sensible MX record... look up the A record
      #print "launching a query for ", server
      newcmd = subprocess.Popen(['host', '-t', 'a', server], stdout=PIPE, stderr=PIPE)
      newcmd.loopcount = MAX_CNAME_LOOP
      newcmd.host = server
      newcmd.orighost = server
      newcmd.type = "a"
      newcmd.callback = process_address_response
      newcmd.priority = priority
      selectors.append(newcmd.stdout)
      queries[newcmd.stdout] = newcmd

def process_address_response(cmd, out, err):

  if not dns_sanity_check(cmd,out, err): return False

  for line in out.split("\n"):
    l = line.strip()
    if not l: continue
    
    if "Truncated, retrying in TCP mode." in l:
      continue

    if " is an alias for " in l:
      return lookup_alias(l, cmd)

    if "has address" not in l:
      sys.stderr.write("weird line\n" + l+ "\n")
  
  print out

def lookup_alias(l, prev_cmd):
  # Recurse to figure out what CNAMEs are pointing at
  inp, _a, newhost = l.partition(" is an alias for ")
  if inp != prev_cmd.host and (inp + ".") != prev_cmd.host:
    sys.stderr.write("Irrelevant cname for %s -> %s\n%s\n" % (prev_cmd.orighost, prev_cmd.host,l) )
    return False
  if any([c not in hostlegal for c in newhost]):
    sys.stderr.write("Bad cname for %s\n%s\n" % (prev_cmd.host,l) )
    return False
  if prev_cmd.loopcount > 0:
    cmd = subprocess.Popen(['host', '-t', prev_cmd.type , newhost], stdout=PIPE, stderr=PIPE)
    cmd.type = prev_cmd.type
    cmd.loopcount = prev_cmd.loopcount - 1
    cmd.orighost = prev_cmd.orighost
    cmd.host = newhost
    cmd.callback = prev_cmd.callback
    selectors.append(cmd.stdout)
    queries[cmd.stdout] = cmd
    return True
  return False

fetch_top_mx_records()
