//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//


#pragma once

#include "sophos_client_runner.hpp"

namespace sse {
    namespace sophos {
        void gen_db(SophosClientRunner& client, size_t N_entries);
        void generate_trace(SophosClientRunner& client, size_t N_entries); 
        void gen_db_with_trace(SophosClientRunner& client, size_t N_entries);
        void eval_trace(SophosClientRunner& client, size_t thread_num);
        void gen_db_2(SophosClientRunner& client, std::string keyword, size_t N_entries);
   }
}
