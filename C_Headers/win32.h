#pragma once

#include "winuser.h"

typedef BOOL(WINAPI* fEnumDesktopsW)(
	IN OPTIONAL  HWINSTA          hwinsta,
	IN           DESKTOPENUMPROCW lpEnumFunc,
	IN           LPARAM           lParam
);