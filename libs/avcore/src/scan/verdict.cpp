#include "avcore/scan/verdict.hpp"

namespace av::scan {

std::string to_string(Verdict verdict) {
    switch (verdict) {
    case Verdict::Clean:
        return "clean";
    case Verdict::Infected:
        return "infected";
    case Verdict::Error:
        return "error";
    }
    return "unknown";
}

}
