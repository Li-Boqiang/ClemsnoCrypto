#ifndef MODOBJECT_H
#define MODOBJECT_H
#include "llvm_basics.h"
#include <boost/functional/hash.hpp>
#include "Utils.h"


enum struct InstModType {
    MPKWrap,
    AllocaInst,
    MemFunc,
    FuncPtr,
    FuncDirect
};


struct InstMod {

    struct CallTarget {
        Function *func;
        InstModType type;
        size_t hash;

        CallTarget() { }

        CallTarget(Function *f, InstModType t, size_t h)
            : func(f), type(t), hash(h) { }
    };

    bool inloop;
    int loopidx;
    Instruction* inst;
    InstModType type;
    bool tainted, ignorepriv;
    std::map<Function*, CallTarget> calltargets;

    InstMod()
        : inst(nullptr), tainted(false), ignorepriv(false) { }

    size_t calcHash() {
        size_t hash = 0;
        boost::hash_combine(hash, Globals::ValueUidMap[inst]);
        boost::hash_combine(hash, type);

        std::map<size_t, CallTarget> tmpMap;
        for (auto &pair: calltargets) {
            tmpMap[Globals::ValueUidMap[pair.first]] = pair.second;
        }

        for (auto &pair: tmpMap) {
            auto &target = pair.second;
            boost::hash_combine(hash, Globals::ValueUidMap[target.func]);
            boost::hash_combine(hash, target.type);
            boost::hash_combine(hash, target.hash);
        }
        return hash;
    }
};

struct FuncMod {
    std::map<Instruction*, InstMod> map;

    std::vector<ReturnInst*> returnlist;
    bool anytainted, isdirector = false, calledbydirector = false;
    int cnt_total, cnt_tainted;

    FuncMod(): anytainted(false), cnt_total(0), cnt_tainted(0) { }

    size_t calcHash() {
        size_t hash = 0;
        std::map<size_t, InstMod> tmpMap;
        for (auto &pair: map) {
            tmpMap[Globals::ValueUidMap[pair.first]] = pair.second;
        }
        for (auto &pair: tmpMap) {
            auto &instmod = pair.second;
            if (instmod.tainted)
                boost::hash_combine(hash, instmod.calcHash());
        }
        return hash;
    }

    InstMod* getInstMod(Instruction &I, InstModType type, bool inloop=false, int loopidx=-1) {
        auto inst = &I;
        auto it = map.find(inst);
        if (it == map.end()) {
            auto &temp = map[inst];
            temp.inst = inst;
            temp.type = type;
            temp.inloop = inloop;
            temp.loopidx = loopidx;
            return &temp;
        }
        return &(it->second);
    }

    InstMod* getInstMod(Instruction &I) {
        auto inst = &I;
        auto it = map.find(inst);
        if (it == map.end()) return nullptr;
        return &(it->second);
    }

    void setTaint(InstMod *instmod) {
        instmod->tainted = true;
        anytainted = true;
    }

    void addCallTarget(InstMod *instmod, Function* func, size_t ctx) {
        instmod->calltargets[func] =
            InstMod::CallTarget(func, InstModType::FuncDirect, ctx);
        setTaint(instmod);
    }

    void addLibFuncCall(InstMod *instmod, Function *func, InstModType type) {
        if (instmod->type != InstModType::FuncPtr) {
            setTaint(instmod);
        } else {
            instmod->calltargets[func] =
                InstMod::CallTarget(func, type, 0);
            setTaint(instmod);
        }
    }
};

#endif //MODOBJECT_H
