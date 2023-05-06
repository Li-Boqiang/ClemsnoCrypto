#ifndef MODIFYVISITOR_H
#define MODIFYVISITOR_H

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include "AliasTaintCtx.h"
#include "Utils.h"
#include "VisitorCallback.h"

struct ModifiedFunction : public FuncMod {
    Function *func;
    size_t ctxhash;
    bool isentry, callerprotect, need_callerprotect;
    Function *newfunc;
    std::unique_ptr<ValueToValueMapTy> vmap;

    ModifiedFunction() : isentry(false), callerprotect(false), newfunc(nullptr) {}

    template <typename T>
    T *resolve_inst(T *val) {
        if (!vmap) return val;
        auto tmp = (*vmap)[val];
        if (!tmp) return val;
        auto ret = dyn_cast<T>(tmp);
        assert(ret);
        return ret;
    }
};

struct ModifiedFunctionList {
    std::map<std::pair<Function *, size_t>, ModifiedFunction> map;
    std::vector<ModifiedFunction *> list;

    ModifiedFunction *tryinsert(AliasTaintContext *ctx) {
        ModifiedFunction tmp;
        tmp.func = ctx->func;
        tmp.map = std::move(ctx->funcmod.map);
        tmp.returnlist = std::move(ctx->funcmod.returnlist);
        tmp.ctxhash = tmp.calcHash();
        tmp.calledbydirector = ctx->funcmod.calledbydirector;
        tmp.isdirector = ctx->funcmod.isdirector;

        auto key = std::make_pair(tmp.func, tmp.ctxhash);
        auto ins = map.emplace(key, std::move(tmp));
        auto modfunc = &(ins.first->second);
        if (ins.second)
            list.push_back(modfunc);
        else {
            modfunc->calledbydirector |= ctx->funcmod.calledbydirector;
            modfunc->isdirector |= ctx->funcmod.isdirector;
        }
        return modfunc;
    }

    void libexports() {
        std::set<Function *> newDirFuncs;
        for (auto &DirFunc : Globals::DirFuncs) {
            for (auto modfunc : list) {
                if (modfunc->func == DirFunc) {
                    newDirFuncs.insert(modfunc->newfunc);
                }
            }
        }
        std::set<ModifiedFunction *> exports;
        for (auto modfunc : list) {
            if (modfunc->calledbydirector && !modfunc->isdirector) exports.insert(modfunc);
        }
        for (auto modfunc : exports) {
            auto target = modfunc->newfunc;
            auto wrapper_name = (modfunc->func->getName() + Globals::ExportLabel).str();
            auto origname = target->getName();
            std::set<CallInst *> calls;
            for (auto user : target->users()) {
                CallSite CS(user);
                CallInst *callinst = cast<CallInst>(CS.getInstruction());
                calls.insert(callinst);
            }
            for (auto callinst : calls)
                funcwrap(target, wrapper_name, callinst, modfunc->need_callerprotect);
            DEBUG_MODIFY(dbgs() << formatv("wrap {0} with {1}\n", origname, wrapper_name));
            (*Globals::ApisReport) << wrapper_name << "\n";
        }
    }
};

struct ModifyCallbackVisitor : public VisitorCallback<AliasTaintContext> {
    static ModifiedFunctionList newfunctions;
    static std::set<Function *> analyzed_functions;

    ModifyCallbackVisitor(AliasTaintContext *&ctx, Module &m) : VisitorCallback(ctx, m) {}

    virtual void visitAllocaInst(AllocaInst &I);
    virtual void visitLoadInst(LoadInst &I);
    virtual void visitStoreInst(StoreInst &I);
    virtual void visitMemTransferInst(MemTransferInst &I);
    virtual void visitMemSetInst(MemSetInst &I);
    virtual bool visitCallInst(CallInst &I, Function *func);
    virtual void visitReturnInst(ReturnInst &I);
    virtual void setupChildContext(CallInst &I, AliasTaintContext *child);
    virtual void stitchChildContext(CallInst &I, AliasTaintContext *child);

    void prestat();
    void poststat();
    void run_modify();

private:
    FuncMod *funcmod() { return &(currCtx->funcmod); }

    void visitLibFunction(CallInst &I, Function *func, InstMod *instmod);
};

#endif  // MODIFYVISITOR_H
