#ifndef CONTEXTBASE_H
#define CONTEXTBASE_H

#include "llvm_basics.h"
#include <utility>
#include <vector>
#include <chrono>


struct timerwrapper {
    typedef std::chrono::steady_clock sysclock;
    sysclock::time_point t1;

    void start() {
        t1 = sysclock::now();
    }

    double get() {
        using namespace std::chrono;
        sysclock::time_point t2 = sysclock::now();
        return duration_cast<duration<double>>(t2 - t1).count();
    }
};


template<typename CtxClass>
struct ContextBase {
    std::vector<CtxClass*> children;
    CtxClass *parent, *self;

    Instruction *inst;
    Function *func;
    bool inside_loop, lastloopiter;
    int loopidx;

    double totaltimer, childtimer;
    timerwrapper timer;

    // timer management

    void init() {
        childtimer = 0;
        timer.start();
    }

    void consume_childctx(CtxClass *rhs) {
        childtimer += rhs->totaltimer;
    }

    std::pair<double, double> get_timer() {
        totaltimer = timer.get();
        return std::make_pair(totaltimer, totaltimer - childtimer);
    }

    // context navigation

    std::pair<CtxClass*, bool> getOrCreateChildCtx(Instruction *inst, Function *func) {
        for (auto ctxptr: children) {
            if (ctxptr->inst == inst && ctxptr->func == func) {
                return std::make_pair(ctxptr, false);
            }
        }
        auto ret = new CtxClass(inst, func);
        ret->parent = self;
        children.push_back(ret);
        return std::make_pair(ret, true);
    }

    bool checkRecursive(Instruction &I) {
        for (auto ctx = self; ctx; ctx = ctx->parent) {
            if (&I == ctx->inst) {
                return true;
            }
        }
        return false;
    }

    // interfaces

    ContextBase(Instruction *inst, Function *func)
            : parent(nullptr), inst(inst), func(func), loopidx(0) {
        self = static_cast<CtxClass*>(this);
    }
    
    void getFuncPtrTargets(Value *fp, std::vector<Function*> &ret) {
        assert(false);
    }
};


#endif  // CONTEXTBASE_H
