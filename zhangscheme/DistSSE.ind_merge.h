/* 
 * Created by Xiangfu Song on 10/21/2016.
 * Email: bintasong@gmail.com
 * 
 */
#ifndef DISTSSE_IND_MERGE_H
#define DISTSSE_IND_MERGE_H

#include "DistSSE.Util.h"

namespace DistSSE {

    // A 'model' merge operator with uint64 addition semantics
    class UInt64AddOperator : public AssociativeMergeOperator {
    public:
        virtual bool Merge(
                const Slice &key,
                const Slice *existing_value,
                const Slice &value,
                std::string *new_value,
                Logger *logger) const override {

            // assuming "" if no existing value
            std::string existing = "";
            if (existing_value) {
                if (!Deserialize(*existing_value, &existing)) {
                    // if existing_value is corrupted, treat it as ""
                    Log(logger, "existing value corruption");
                    existing = "";
                }
            }

            std::string oper;
            if (!Deserialize(value, &oper)) {
                // if operand is corrupted, treat it as 0
                Log(logger, "operand value corruption");
                oper = 0;
            }

            auto
            new = existing + oper;
            *new_value = Serialize(new);
            return true;        // always return true for this, since we treat all errors as "zero".
        }

        virtual const char *Name() const override {
            return "UInt64AddOperator";
        }
    };
// ==========================================

    class MergeBasedIndentifier {

    public:
        MergeBasedIndentifier(std::shared_ptr <rocksdb::DB> db);

        // mapped to a leveldb Merge operation
        virtual void Append(const string &key, std::string ind) override {
            string serialized = Serialize(value);
            db_->Merge(merge_option_, key, serialized);
        }

    }; // MergeBasedIndentifier



} // namespace DistSSE

#endif // DISTSSE_IND_MERGE_H
