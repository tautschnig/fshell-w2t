#!/usr/bin/python

from __future__ import print_function
from pycparser import c_ast, parse_file
from pycparserext import ext_c_generator, ext_c_parser

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
#import xml.etree.CElementTree as ElementTree
import xml.etree.ElementTree as ElementTree


def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)


def validateConfig(graph, ns, witness, benchmark, bitwidth):
  config = {}
  for k in graph.findall('./graphml:data', ns):
    key = k.get('key')
    config[key] = k.text

  for k in ['witness-type', 'sourcecodelang', 'architecture', 'programhash']:
    if config.get(k) is None:
      eprint('INVALID WITNESS FILE: mandatory field {} missing'.format(k))
      sys.exit(1)

  if config['witness-type'] != 'violation_witness':
    raise ValueError('No support for ' + config['witness-type'])

  if config['sourcecodelang'] != 'C':
    raise ValueError('No support for language ' + config['sourcecodelang'])

  if config['architecture'] != '{}bit'.format(bitwidth):
    raise ValueError('Architecture mismatch')

  with open(benchmark, 'rb') as b:
    sha1hash = hashlib.sha1(b.read()).hexdigest()
    if config['programhash'] != sha1hash:
      # eprint('INVALID WITNESS FILE: SHA1 mismatch')
      # sys.exit(1)
      eprint('WARNING: SHA1 mismatch')

  spec = re.sub(r'\s+', '', config['specification'])
  spec = re.sub(r'\n', '', spec)
  return re.sub(r'^CHECK\(init\((\S+?)\(\)\),LTL\((\S+)\)\).*', '\g<1>', spec)


def setupTypes(ast, entryFunc, inputs, nondets, entry, typedefs):
  for fun in ast.ext:
    if isinstance(fun, c_ast.Decl) and isinstance(fun.type, c_ast.FuncDecl):
      if fun.name.startswith('__VERIFIER_nondet_'):
        info = {}
        info['type'] = ext_c_generator.GnuCGenerator().visit(fun.type)
        info['line'] = fun.coord.line
        nondets[fun.name] = info
    if isinstance(fun, c_ast.Decl) and isinstance(fun.type, ext_c_parser.FuncDeclExt):
      if fun.name.startswith('__VERIFIER_nondet_'):
        info = {}
        info['type'] = ext_c_generator.GnuCGenerator().visit(fun)
        info['type'] = re.sub(r'^extern ', '', info['type'])
        info['line'] = fun.coord.line
        nondets[fun.name] = info
    elif isinstance(fun, c_ast.FuncDef):
      inputs[fun.decl.name] = {}
      if fun.body.block_items:
        for d in fun.body.block_items:
          if isinstance(d, c_ast.Decl):
            info = {}
            typestr = ext_c_generator.GnuCGenerator().visit(d)
            if d.name is not None:
                typestr = re.sub(r'\b%s\b' % re.escape(d.name), '', typestr)
            if typedefs.get(typestr):
                typestr = typedefs[typestr]
            info['type'] = typestr
            info['line'] = d.coord.line
            if d.init is None:
              inputs[fun.decl.name][d.name] = info
      if fun.decl.name == entryFunc:
        entry['type'] = ext_c_generator.GnuCGenerator().visit(fun.decl.type)
        entry['line'] = fun.coord.line
    elif isinstance(fun, c_ast.Typedef):
      name = fun.name
      if isinstance(fun.type, ext_c_parser.FuncDeclExt):
        typestr = ext_c_generator.GnuCGenerator().visit(fun.type.type) + ('()' +
          '(' + ext_c_generator.GnuCGenerator().visit(fun.type.args) + ')')
        name = fun.name + ' (*)'
      elif isinstance(fun.type, c_ast.PtrDecl) and isinstance(fun.type.type,
              ext_c_parser.FuncDeclExt):
        typestr = ext_c_generator.GnuCGenerator().visit(fun.type.type.type) + ('(*)' +
          '(' + ext_c_generator.GnuCGenerator().visit(fun.type.type.args) + ')')
      else:
        typestr = ext_c_generator.GnuCGenerator().visit(fun.type)
        typestr = re.sub(r'^(struct|union)\s+[a-zA-Z_0-9]+\s*\{', r'\1 {',
                            typestr)
      while typedefs.get(typestr):
        typestr = typedefs.get(typestr)
      typedefs[name] = typestr


def setupWatch(ast, watch):
  class FuncCallVisitor(c_ast.NodeVisitor):
    def __init__(self, watch):
      self.watch = watch

    def visit_FuncCall(self, node):
      if (isinstance(node.name, c_ast.ID) and
          node.name.name.startswith('__VERIFIER_nondet_')):
        l = node.name.coord.line
        assert self.watch.get(l) is None or self.watch[l] == node.name.name
        self.watch[l] = node.name.name

  v = FuncCallVisitor(watch)
  v.visit(ast)


def checkTrace(trace, entryNode, violationNode):
  n = entryNode
  while trace[n].get('target') is not None:
    n = trace[n]['target']
  if violationNode and n != violationNode:
    eprint("INVALID WITNESS FILE: trace does not end in violation node")
    sys.exit(1)


def buildTrace(graph, ns, trace):
  entryNode = None
  violationNode = None
  sinks = {}
  for n in graph.findall('./graphml:node', ns):
    i = n.get('id')
    trace[i] = {}
    for d in n.findall('./graphml:data', ns):
      if d.get('key') == 'entry' and d.text == 'true':
        assert entryNode is None
        entryNode = i
      elif d.get('key') == 'violation' and d.text == 'true':
        assert violationNode is None
        violationNode = i
      elif d.get('key') == 'sink' and d.text == 'true':
        sinks[i] = True
  if entryNode is None:
    eprint("INVALID WITNESS FILE: no entry node")
    sys.exit(1)
  if violationNode is None:
    eprint("WARNING: no violation node")

  for e in graph.findall('./graphml:edge', ns):
    s = e.get('source')
    t = e.get('target')
    if violationNode and s == violationNode:
      continue
    elif sinks.get(t) is not None:
      continue
    # only linear traces supported
    assert trace[s].get('target') is None
    trace[s]['target'] = t
    for d in e.findall('./graphml:data', ns):
      key = d.get('key')
      trace[s][key] = d.text

  checkTrace(trace, entryNode, violationNode)

  return entryNode


def processWitness(witness, benchmark, bitwidth):
  try:
    root = ElementTree.parse(witness).getroot()
  except:
    eprint("INVALID WITNESS FILE: failed to parse XML")
    sys.exit(1)
  # print(ElementTree.tostring(root))
  ns = {'graphml': 'http://graphml.graphdrawing.org/xmlns'}
  graph = root.find('./graphml:graph', ns)
  if graph is None:
    eprint("INVALID WITNESS FILE: failed to parse XML - no graph node")
    sys.exit(1)

  entryFun = validateConfig(graph, ns, witness, benchmark, bitwidth)

  benchmarkString = ''
  with tempfile.NamedTemporaryFile() as fp:
    # preprocess and remove __attribute__
    subprocess.check_call(['gcc', '-D__attribute__(x)=', '-x', 'c', '-E', benchmark, '-o', fp.name])
    with open(fp.name, 'r') as b:
      needStructBody = False
      skipAsm = False
      inVaArg = 0
      inOffsetOf = 0
      for line in b:
        # rewrite some GCC extensions
        """
        line = re.sub(r'__extension__\s*\(\{\s*if\s*\(0\)\s*;\s*else\s+(__assert_fail\s*\("0",\s*".*",\s*\d+,\s*__extension__\s+__PRETTY_FUNCTION__\s*\));\s*\}\)', r'\1', line)
        """
        line = re.sub(r'\b__extension__\b', '', line)
        """
        line = re.sub(r'\b__restrict\b', 'restrict', line)
        line = re.sub(r'\b__inline__\b', 'inline', line)
        line = re.sub(r'\b__inline\b', 'inline', line)
        line = re.sub(r'\b__const\b', 'const', line)
        """
        line = re.sub(r'\b__signed__\b', 'signed', line)
        """
        line = re.sub(r'\b__builtin_va_list\b', 'int', line)
        """
        line = re.sub(r'\b__thread\b', '', line)
        # a hack for some C-standards violating code in LDV benchmarks
        if needStructBody and re.match(r'^\s*}\s*;\s*$', line):
          line = 'int __dummy; ' + line
          needStructBody = False
        elif needStructBody:
          needStructBody = re.match(r'^\s*$', line) is not None
        elif re.match(r'^\s*struct\s+[a-zA-Z0-9_]+\s*{\s*$', line):
          needStructBody = True
        # remove inline asm
        if re.match(r'^\s*__asm__(\s+volatile)?\s*\("([^"]|\\")*"[^;]*$', line):
          skipAsm = True
        elif skipAsm and re.search(r'\)\s*;\s*$', line):
          line = '\n'
          skipAsm = False
          line = '\n'
        if (skipAsm or
            re.match(r'^\s*__asm__(\s+volatile)?\s*\("([^"]|\\")*"[^;]*\)\s*;\s*$', line)):
          line = '\n'
        # remove asm renaming
        line = re.sub(r'__asm__\s*\(""\s+"[a-zA-Z0-9_]+"\)', '', line)
        # pycparser cannot handle the type spec in va_arg
        if re.search(r'__builtin_va_arg\s*\([^,]+,[^\)]+\)', line):
            line = re.sub(r'(__builtin_va_arg\([^,]+),[^\)]+\)', r'\1)', line)
        elif re.search(r'__builtin_va_arg\s*\(\s*$', line):
            inVaArg = 1
        elif inVaArg == 1:
            inVaArg = 2
        elif inVaArg == 2:
            if not re.match(r'^\s*,\s*$', line):
                inVaArg = 0
            else:
                inVaArg = 3
                line = '\n'
        elif inVaArg == 3:
            if re.search(r';\*$', line):
                inVaArg = 0
                line = ',' + line
            else:
                inVaArg = 4
                line = '\n'
        elif inVaArg == 4:
            assert re.match(r'^\s*\)\s*$', line)
            inVaArg = 5
        elif inVaArg == 5:
            assert re.match(r'^\s*;\s*$', line)
            inVaArg = 0
        # pycparser cannot handle the type spec in __builtin_offsetof
        if re.search(r'__builtin_offsetof\s*\([^,]+,[^\)]+\)', line):
            line = re.sub(r'__builtin_offsetof\s*\([^,]+,[^\)]+\)', '0', line)
        elif re.search(r'__builtin_offsetof\s*\(\s*$', line):
            line = re.sub(r'__builtin_offsetof\s*\(\s*$', '0\n', line)
            inOffsetOf = 1
        elif inOffsetOf == 1:
            inOffsetOf = 2
            line = '\n'
        elif inOffsetOf == 2:
            assert re.match(r'^\s*,\s*$', line)
            inOffsetOf = 3
            line = '\n'
        elif inOffsetOf == 3:
            inOffsetOf = 4
            line = '\n'
        elif inOffsetOf == 4:
            assert re.match(r'^\s*\)\s*$', line)
            inOffsetOf = 0
            line = '\n'
        benchmarkString += line
  parser = ext_c_parser.GnuCParser()
  ast = parser.parse(benchmarkString, filename=benchmark)
  # ast.show(showcoord=True, buf=sys.stderr)

  inputs = {}
  nondets = {}
  entry = {}
  typedefs = {}
  setupTypes(ast, entryFun, inputs, nondets, entry, typedefs)
  assert entry
  watch = {}
  setupWatch(ast, watch)

  trace = {}
  entryNode = buildTrace(graph, ns, trace)

  values = []
  n = entryNode
  missing_nondets = set(nondets)
  while trace[n].get('target') is not None:
    if trace[n].get('assumption') is not None:
      # assumptions may use = or ==
      a = re.sub(r'==', '=', trace[n]['assumption'])
      a = re.sub(r'\\result', '__SV_COMP_result', a)
      # we may be missing typedefs used in type casts
      a_copy = a
      if re.search(r'\(\s*[a-zA-Z_][a-zA-Z0-9_]*.*\)', a):
          # do two rounds - strictly speaking, we'd need a fixed point here
          do_not_repeat = False
          for t in typedefs:
              a_before = a
              if t.endswith(' (*)'):
                a = re.sub(r'%s' % re.escape(t), typedefs[t], a)
              else:
                a = re.sub(r'\b%s\b' % re.escape(t), typedefs[t], a)
              if 'struct struct' in a:
                  a = a_before
                  do_not_repeat = True
          if not do_not_repeat:
              for t in typedefs:
                  if t.endswith(' (*)'):
                    a = re.sub(r'%s' % re.escape(t), typedefs[t], a)
                  else:
                    a = re.sub(r'\b%s\b' % re.escape(t), typedefs[t], a)
      wrapped = 'void foo() { ' + a + ';}'
      try:
        block_items = parser.parse(wrapped).ext[0].body.block_items
      except:
        eprint('Failed to parse ' + wrapped + '(expanded from ' + a_copy + ')')
        raise
      for a_ast in block_items:
        if isinstance(a_ast, c_ast.Assignment):
          f = trace[n].get('assumption.scope')
          v = ext_c_generator.GnuCGenerator().visit(a_ast.rvalue)
          v = re.sub(r'\n', ' ', v)
          if (trace[n].get('startline') is not None and
              watch.get(int(trace[n]['startline'])) is not None):
            w = watch[int(trace[n]['startline'])]
            values.append([w, v])
            if w in missing_nondets:
              missing_nondets.remove(w)
          elif (f is not None and
                isinstance(a_ast.lvalue, c_ast.ID) and
                inputs.get(f) is not None and
                inputs[f].get(a_ast.lvalue.name) is not None):
            values.append([f, a_ast.lvalue.name, v])
          # else:
          #   print(trace[n]['startline'])
          #   a_ast.show()
        # else:
        #   print(trace[n]['startline'])
        #   a_ast.show()

    n = trace[n]['target']

  if watch and not values:
    eprint('inputs: ')
    eprint(inputs)
    eprint('nondets: ')
    eprint(nondets)
    eprint('watch: ')
    eprint(watch)
    eprint("WARNING: no input values found in witness file, behaviour of harness may be undefined")

  print('IN:')
  print('  ENTRY {n}()@[file {f} line {l}]'.format(
        n=entryFun, f=benchmark, l=entry['line']))

  for v in values:
    if len(v) == 3:
      info = inputs[v[0]][v[1]]
      print('  {t} {n}@[file {f} line {l} function {fun}]={value}'.format(
            t=info['type'], n=v[1], f=benchmark, l=info['line'], fun=v[0],
            value=v[2]))
    else:
      info = nondets[v[0]]
      print('  {t}@[file {f} line {l}]={value}'.format(
            t=info['type'], f=benchmark, l=info['line'], value=v[1]))

  for n in missing_nondets:
      info = nondets[n]
      print('  {t}@[file {f} line {l}]=0'.format(
            t=info['type'], f=benchmark, l=info['line']))


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-w', '--witness', type=str, required=True,
                      help='graphml witness file')
  parser.add_argument('-b', '--benchmark', type=str, required=True,
                      help='benchmark file')
  parser.add_argument('-m', type=int,
                      help='bit width of system architecture')
  args = parser.parse_args()

  processWitness(args.witness, args.benchmark, args.m)


if __name__ == '__main__':
  main()
