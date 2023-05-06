#ifndef LLVM_BASICS_H
#define LLVM_BASICS_H
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/raw_ostream.h>
using namespace llvm;

#define DEBUG_PASSENTRY(msg) DEBUG_WITH_TYPE("entry", msg)
#define DEBUG_GVISITOR(msg) DEBUG_WITH_TYPE("gvisitor", msg)
#define DEBUG_CTXTIME(msg)  DEBUG_WITH_TYPE("ctxtime", msg)
#define DEBUG_GLOBOBJ(msg)  DEBUG_WITH_TYPE("globobj", msg)
#define DEBUG_CALLINST(msg) DEBUG_WITH_TYPE("callinst", msg)
#define DEBUG_LOADSTOR(msg) DEBUG_WITH_TYPE("loadstor", msg)
#define DEBUG_MODIFY(msg) DEBUG_WITH_TYPE("modify", msg)

#endif  // LLVM_BASICS_H
