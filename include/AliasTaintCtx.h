#ifndef ALIASTAINTCTX_H
#define ALIASTAINTCTX_H

#include <vector>
#include <memory>
#include <map>
#include <set>
#include "ContextBase.h"
#include "ModObject.h"


struct AliasObject;
typedef int FieldIdTy;


struct PointsTo {
    FieldIdTy dstoff;
    AliasObject *target;
    Instruction *propagator;

    PointsTo(AliasObject *obj, FieldIdTy off, Instruction *inst)
        : dstoff(off), target(obj), propagator(inst) { }
    
    bool operator<(const PointsTo &rhs) const {
        if (target == rhs.target)
            return dstoff < rhs.dstoff;
        return target < rhs.target;
    }
};


struct FieldObject {
    bool ignoresink;
    std::set<PointsTo> pointsto;
    int taintflag, sinktaint;
    Instruction *tainter, *sinktainter;

    FieldObject(): ignoresink(false), taintflag(0), sinktaint(0), tainter(nullptr), sinktainter(nullptr) { }

    void addPointsTo(AliasObject *obj, FieldIdTy off, Instruction *inst) {
        pointsto.insert(PointsTo(obj, off, inst));
    }

    void mergePointsTo(FieldObject *src, Instruction *inst) {
        for (auto &item: src->pointsto) {
            auto tmp = item;
            tmp.propagator = inst;
            pointsto.insert(tmp);
        }
    }

    void flowTaint(FieldObject *src, Instruction *inst) {
        if (src->sinktaint) {
            sinktaint = src->sinktaint;
            sinktainter = inst;
        }
        if ((!src->sinktaint || ignoresink) && src->taintflag) {
#ifndef ONLY_MASTERKEY
            taintflag = src->taintflag;
            tainter = inst;
#endif
        }
        // if (src->ignoresink && src->taintflag) {
        //     dbgs() << "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHH\n";
        // }
    }

    void setTaint(Instruction *inst) {
        taintflag = 1;
        tainter = inst;
    }
    
    void setSinkTaint(Instruction *inst) {
        sinktaint = 1;
        taintflag = 0;
        tainter = nullptr;
        sinktainter = inst;
    }
};


struct RegObject: public FieldObject {
    Value *represented;

    RegObject(Value* obj): represented(obj) { }
};


inline bool hasPointsTo(FieldObject *reg) {
    return reg && reg->pointsto.size();
}


inline bool hasTaint(FieldObject *reg) {
    return reg && (reg->taintflag || reg->sinktaint);
}


struct AliasObject {
    std::map<FieldIdTy, FieldObject> fieldmap;
    Value *represented;
    bool fake, tainted, sink;
    Instruction *tainter;

    AliasObject(Value* obj)
        : represented(obj), fake(false), tainted(false), sink(false), tainter(nullptr) { }

    FieldObject* findFieldObj(FieldIdTy fid) {
        auto it = fieldmap.find(fid);
        if (it != fieldmap.end())
            return &(it->second);
        return nullptr;
    }

    FieldObject* getFieldObj(FieldIdTy fid) {
        return &(fieldmap[fid]);
    }

    void updateTaintByField(FieldIdTy fid, FieldObject* fobj) {
        if ((fobj->sinktaint && !fobj->ignoresink)) {
            sink = true;
            tainted = false;
        }
        // if (fobj->taintflag && sink) {
        //     DEBUG_LOADSTOR(dbgs() << "hello" << "\n");
        // }
        if (fobj->taintflag && !sink && !tainted) {
            tainted = true;
            tainter = fobj->tainter;
        }
    }

    bool isstackobj() {
        if (represented && dyn_cast<AllocaInst>(represented))
            return true;
        else 
            return false;
    }
};


inline bool checkPointsToTaint(FieldObject *reg, bool ignorestack=false) {
    for (auto &pt: reg->pointsto)
        if ((!ignorestack || !pt.target->isstackobj()) && pt.target->tainted)
            return true;
    return false;
}

inline bool checkPointsToSink(FieldObject *reg, bool ignorestack=false) {
    for (auto &pt: reg->pointsto)
        if ((!ignorestack || !pt.target->isstackobj()) && pt.target->sink)
            return true;
    return false;
}

struct ObjectMap {
    std::map<Value*, std::unique_ptr<RegObject> > regmap;
    std::map<Value*, std::unique_ptr<AliasObject> > memmap;

    std::pair<RegObject*, AliasObject*> createRegMemPair(Value *val) {
        auto regs = getOrCreateObject<RegObject>(regmap, val);
        auto mems = getOrCreateObject<AliasObject>(memmap, val);
        if (regs.second || mems.second) {
            auto inst = static_cast<Instruction*>(val);
            regs.first->addPointsTo(mems.first, 0, inst);
        }
        return std::make_pair(regs.first, mems.first);
    }

    RegObject* getRegObj(Value *val) {
        return getOrCreateObject<RegObject>(regmap, val).first;
    }

    RegObject* findRegObj(Value *val) {
        return getNoCreateObject<RegObject>(regmap, val);
    }

    AliasObject* findMemObj(Value *val) {
        return getNoCreateObject<AliasObject>(memmap, val);
    }

private:
    template<typename T, typename Map>
    T* getNoCreateObject(Map &map, Value *val) {
        auto it = map.find(val);
        if (it != map.end())
            return it->second.get();
        return nullptr;
    }

    template<typename T, typename Map>
    std::pair<T*, bool> getOrCreateObject(Map &map, Value *val) {
        auto ins = map.emplace(val, std::unique_ptr<T>(nullptr));
        auto &uptr = ins.first->second;
        if (ins.second) uptr.reset(new T(val));
        return std::make_pair(uptr.get(), ins.second);
    }
};


struct AliasTaintContext: public ContextBase<AliasTaintContext> {
    static ObjectMap globalobjects;
    ObjectMap localobjects;
    std::set<Value*> retval;
    FuncMod funcmod;
    bool isdirector;

    // MemObj management

    std::pair<RegObject*, AliasObject*>
    createRegMemPair(Value *val, bool fake = false) {
        auto ret = localobjects.createRegMemPair(val);
        // later create may overwrite previous fake flag
        ret.second->fake = fake;
        return ret;
    }

    // RegObj management

    RegObject* getDestReg(Value *val) {
        auto newval = val->stripPointerCasts();
        if (newval != val) return getDestReg(newval);
        // no new globalobjects will be created
        if (isa<GlobalObject>(val))
            return globalobjects.findRegObj(val);
        return localobjects.getRegObj(val);
    }

    RegObject* findOpReg(Value *val) {
        auto newval = val->stripPointerCasts();
        if (newval != val) return findOpReg(newval);
        if (isa<GlobalObject>(val))
            return globalobjects.findRegObj(val);
        auto ret = localobjects.findRegObj(val);
        // create missing pointees on last round of loop
        if (!ret && !inside_loop && val->getType()->isPointerTy()
                 && !isa<ConstantPointerNull>(val)) {
            DEBUG_LOADSTOR(dbgs() << "findOpReg failed: " << *val << "\n");
            ret = createRegMemPair(val, true).first;
        }
        return ret;
    }

    // interfaces

    static void setupGlobals(Module &m);

    AliasTaintContext(Instruction *inst, Function *func)
        : ContextBase(inst, func), isdirector(false) { }

    void getFuncPtrTargets(Value *fp, std::vector<Function*> &ret);
};


#endif  // ALIASTAINTCTX_H
