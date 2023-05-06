#include "llvm_basics.h"
#include <llvm/Pass.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/ADT/SmallSet.h>
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SourceMgr.h"
#include <fstream>
#include "ContextBase.h"
#include "GlobalVisitor.h"
#include "AliasAnalysisVisitor.h"
#include "TaintAnalysisVisitor.h"
#include "ModifyVisitor.h"
#include "Utils.h"


static cl::opt<std::string> CheckFunctionName("toCheckFunction",
        cl::desc("Function which is to be considered as entry point "
            "into the program"),
        cl::value_desc("full name of the function"), cl::init(""));

static cl::opt<std::string> CreateLib("createLib",
        cl::desc("Director functions"),
        cl::value_desc("file of function's full name"), cl::init(""));

static cl::opt<std::string> ExportLabel("exportLabel",
        cl::desc("suffix of exported functions"),
        cl::value_desc("suffix of exported functions"), cl::init(""));

static cl::opt<std::string> Threshold("threshold",
        cl::desc("Threshold for full-protection"),
        cl::value_desc("double"), cl::init(""));

static cl::opt<std::string> ApisReportFile("apisReport",
        cl::desc("Report of API names exported"),
        cl::value_desc("file to output API names"), cl::init(""));

static cl::opt<std::string> TaintReportFile("taintReport",
        cl::desc("Report of taints"),
        cl::value_desc("file name"), cl::init(""), cl::Required);

static cl::opt<std::string> DbgBc("debugbc",
        cl::desc("Debug version of bitcode"),
        cl::value_desc("llvm bitcode"), cl::init(""), cl::Required);

static cl::opt<std::string> HotspotsFile("hotspots",
        cl::desc("Hotspot functions"),
        cl::value_desc("text"), cl::init(""));

static cl::opt<std::string> SkipFile("skipfuncs",
        cl::desc("Functions to skip"),
        cl::value_desc("text"), cl::init(""));

bool Globals::IsLib = false;
double Globals::Threshold = 0.5;
std::map<Value *, std::size_t> Globals::ValueUidMap;
std::set<Function *> Globals::DirFuncs;
std::set<std::string> Globals::Hotspots;
std::set<std::string> Globals::SkipFuncs;
std::string Globals::ExportLabel;
std::map<std::size_t, Value *> DbgInfo::DbgUidValueMap;
raw_fd_ostream *Globals::ApisReport = nullptr;
raw_fd_ostream *Globals::TaintReport = nullptr;
Module *DbgInfo::DbgM = nullptr;

struct SAAPass: public ModulePass {
    static char ID;

    SAAPass(): ModulePass(ID) {}

    ~SAAPass() {}

    static void init(Module &m) {
        splitConstExpr(m);
        initValueUid(m, Globals::ValueUidMap);
        DbgInfo::load(DbgBc);
        Globals::ExportLabel = std::move(ExportLabel);
        if (CreateLib != "") {
            std::ifstream ifile(CreateLib);
            std::string line;
            while (std::getline(ifile, line)) {
                Globals::DirFuncs.insert(m.getFunction(line));
            }
            ifile.close();
            Globals::IsLib = true;

            static std::error_code EC;
            static raw_fd_ostream Output(ApisReportFile, EC, sys::fs::OF_Append);
            Globals::ApisReport = &Output;
        }
        if (HotspotsFile != "") {
            std::ifstream ifile(HotspotsFile);
            std::string line;
            while (std::getline(ifile, line)) {
                Globals::Hotspots.insert(line);
            }
            ifile.close();
        }
        if (SkipFile != "") {
            std::ifstream ifile(SkipFile);
            std::string line;
            while (std::getline(ifile, line)) {
                Globals::SkipFuncs.insert(line);
            }
            ifile.close();
        }
        static std::error_code EC;
        static raw_fd_ostream Output(TaintReportFile, EC, sys::fs::OF_Append);
        Globals::TaintReport = &Output;
        if (Threshold != "")
            Globals::Threshold = atof(Threshold.c_str());
    }

    bool runOnModule(Module &m) override {
        init(m);
        for (Function &func: m) {
            if (func.getName().str() == CheckFunctionName) {
                errs() << "Entry Point Found!\n";
                start_analyze(m, func);
                break;
            }
        }
        replaceRuntime(m);
        //if (Globals::IsLib) {
        //    Globals::ApisReport->close();
        //}
        //Globals::TaintReport->close();
        return true;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.setPreservesAll();
        AU.addRequired<LoopInfoWrapperPass>();
    }

    void start_analyze(Module &m, Function &entry) {
        GlobalVisitor<AliasTaintContext> visitor(m, entry);
        visitor.addCallback<AliasAnalysisVisitor>();
        visitor.addCallback<TaintAnalysisVisitor>();
        visitor.analyze();
        visitor.clearCallbacks();
        DEBUG_PASSENTRY(dbgs() << "ModifyVisitor analyze\n");
        auto modifyvisitor = visitor.addCallback<ModifyCallbackVisitor>();
        visitor.analyze();
        modifyvisitor->run_modify();
    }
};


char SAAPass::ID = 0;
static RegisterPass<SAAPass> x("dr_checker", "Soundy Program Rewriter");
