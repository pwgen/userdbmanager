find_path( CRYPT_INCLUDE_DIR
    NAMES crypt.h
    HINTS
        ${CMAKE_INSTALL_INCLUDEDIR}
    NO_CACHE
)

find_library( 
    NAMES crypt
    HINTS
        ${CMAKE_INSTALL_LIBDIR}
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args(
    Crypt
    REQUIRED_VARS CRYPT_LIBRARIES CRYPT_INCLUDE_DIR
)

mark_as_advanced( CRYPT_INCLUDE_DIR CRYPT_LIBRARIES )
find_package_message(Crypt
	"Found Crypt libraries: ${CRYPT_LIBRARIES}"
	"Found Crypt includes ${CRYPT_INCLUDE_DIR}"
)

