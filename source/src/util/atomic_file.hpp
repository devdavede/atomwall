#pragma once

#include <string>
#include <string_view>
#include <sys/types.h>

namespace atomwall {

enum class ExistingFileMode {
    // The file ends up with exactly `mode`, tightening a looser one left by an
    // older version. For files holding secrets.
    Reset,
    // If the file already exists it keeps its current permission bits (so an
    // operator's chmod/chgrp survives an admin-API rewrite); `mode` applies
    // only when the file is being created.
    Preserve,
};

// Replaces `path` with `contents` such that neither a reader nor a crash ever
// sees a partial file: written to path + ".tmp", fsync'd, then renamed over
// `path`. Throws std::runtime_error — with `path` left untouched and the temp
// file removed — if any step fails (disk full, I/O error, ...). Never renames
// an incompletely-written file into place.
//
// The temp file is created with `mode` from the start (not the process umask
// default) and fchmod'd explicitly, so it's never even briefly more
// permissive than intended.
void write_file_atomically(const std::string& path, std::string_view contents, mode_t mode,
                            ExistingFileMode existing = ExistingFileMode::Reset);

} // namespace atomwall
