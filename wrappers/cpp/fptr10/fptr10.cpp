/**
 * AUTO GENERATED FILE
 */

#include <stdint.h>

#include "fptr10.h"
#include "utf8cpp/utf8.h"

#if defined(DTOX_OS_LINUX_FAMILY) || defined(DTOX_OS_APPLE_FAMILY)
# define PATH_SEPARATOR "/"
# define PATH_SEPARATOR_C '/'
# define PATH_SEPARATOR_W L"/"
# define PATH_SEPARATOR_WC L'/'
#else
# define PATH_SEPARATOR "\\"
# define PATH_SEPARATOR_C '\\'
# define PATH_SEPARATOR_W L"\\"
# define PATH_SEPARATOR_WC L'\\'
#endif

#if defined(DTOX_OS_LINUX_FAMILY) || defined(DTOX_OS_APPLE_FAMILY)

#include <dlfcn.h>
#include <stdexcept>

# define GET_PROC(h, n)        dlsym(h, n)
# define LOAD_LIBRARY(lib)     dlopen(lib, RTLD_LAZY)
# define UNLOAD_LIBRARY(h)     dlclose(h)
# define JAVAPATH_DELIM        L":"

#elif defined(DTOX_OS_WINDOWS_FAMILY)

# include <windows.h>

# define JAVAPATH_DELIM        L";"
# if defined(DTOX_OS_WINDOWS)
#  define GET_PROC(h, n)       GetProcAddress(h, n)
#  define LOAD_LIBRARY(lib)    LoadLibraryW(lib)
#  define UNLOAD_LIBRARY(h)    FreeLibrary(h)
# elif defined(DTOX_OS_WINCE)
#  define GET_PROC(h, n)       GetProcAddressA(h, n)
#  define LOAD_LIBRARY(lib)    LoadLibraryW(lib)
#  define UNLOAD_LIBRARY(h)    FreeLibrary(h)
# elif defined(DTOX_OS_WINRT)
#  define GET_PROC(h, n)       GetProcAddress(h, n)
#  define LOAD_LIBRARY(lib)    LoadPackagedLibrary(lib, 0)
#  define UNLOAD_LIBRARY(h)    FreeLibrary(h)
# endif

#else

# error "Unsupported platform"

#endif

namespace Atol
{
namespace Fptr
{

std::string utf8(const std::wstring &src)
{
    if (src.empty())
        return "";

    std::vector<char> dest;

    try
    {
        for (size_t i = 0; i < src.length(); ++i)
            utf8::append((uint32_t) src[i], std::back_inserter(dest));
    }
    catch (...)
    {
    }

    if (dest.empty())
        return "";
    return std::string(&dest[0], dest.size());
}

std::wstring defaultLibraryPath()
{
    std::wstring result;
#ifdef DTOX_OS_WINDOWS_FAMILY
    HKEY hKey = 0;
    LONG lRes = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                             L"SOFTWARE\\ATOL\\Drivers\\10.0\\KKT",
                             0,
                             KEY_READ,
                             &hKey);
    if (lRes == ERROR_SUCCESS)
    {
        WCHAR szBuffer[1024] = {0};
        DWORD dwBufferSize = sizeof(szBuffer);
        ULONG nError = RegQueryValueEx(hKey,
                                       L"INSTALL_DIR",
                                       0,
                                       NULL,
                                       (LPBYTE) szBuffer,
                                       &dwBufferSize);
        if (ERROR_SUCCESS == nError)
        {
            result = szBuffer;
            result += L"\\bin";
        }
    }
    RegCloseKey(hKey);
#else

#endif
    return result;
}

Fptr::Fptr(const std::wstring &libraryPath)
    : m_library(0)
    , m_fptr(0)
{
    std::wstring loadPath = libraryPath;
    if (loadPath.empty())
        loadPath = defaultLibraryPath() + PATH_SEPARATOR_W;
    if (loadPath == PATH_SEPARATOR_W)
        loadPath = L"";

#ifdef DTOX_OS_LINUX_FAMILY
    m_library = LOAD_LIBRARY((utf8(loadPath) + "libfptr10.so").c_str());
    if (!m_library)
    {
        throw std::runtime_error("libfptr10.so not found");
    }
#elif defined(DTOX_OS_MAC)
    m_library = LOAD_LIBRARY((utf8(loadPath) + "fptr10.framework/fptr10").c_str());
    if (!m_library)
    {
        m_library = LOAD_LIBRARY((utf8(loadPath) + "libfptr10.dylib").c_str());
        if (!m_library)
        {
            throw std::runtime_error(std::string("fptr10 not found (") + dlerror() + ")");
        }
    }
#else
    if (!LOAD_LIBRARY((loadPath + L"msvcp140.dll").c_str()))
    {
        throw std::runtime_error("msvcp140.dll not found");
    }

    m_library = LOAD_LIBRARY((loadPath + L"fptr10.dll").c_str());
    if (!m_library)
    {
        throw std::runtime_error("fptr10.dll not found");
    }
#endif

    loadMethods();

    m_createMethod(&m_fptr);
}

void Fptr::loadMethods()
{
#define FIND_FUNC(type, var, name, ignoreError) \
    var = (type) GET_PROC(m_library, name); \
    if (!var && !ignoreError) \
        throw std::runtime_error("method " name "() not found")

    FIND_FUNC(GET_VERSION_STRING_METHOD, m_getVersionMethod, "libfptr_get_version_string", 1);

    FIND_FUNC(CREATE_METHOD, m_createMethod, "libfptr_create", 1);
    FIND_FUNC(DESTROY_METHOD, m_destroyMethod, "libfptr_destroy", 1);

    FIND_FUNC(SET_SETTINGS_METHOD, m_setSettingsMethod, "libfptr_set_settings", 1);
    FIND_FUNC(GET_SETTINGS_METHOD, m_getSettingsMethod, "libfptr_get_settings", 1);
    FIND_FUNC(SET_SINGLE_SETTING_METHOD, m_setSingleSettingMethod, "libfptr_set_single_setting", 1);
    FIND_FUNC(GET_SINGLE_SETTING_METHOD, m_getSingleSettingMethod, "libfptr_get_single_setting", 1);

    FIND_FUNC(IS_OPENED_METHOD, m_isOpenedMethod, "libfptr_is_opened", 1);

    FIND_FUNC(ERROR_CODE_METHOD, m_errorCodeMethod, "libfptr_error_code", 1);
    FIND_FUNC(ERROR_DESCRIPTION_METHOD, m_errorDescriptionMethod, "libfptr_error_description", 1);
    FIND_FUNC(RESET_ERROR_METHOD, m_resetErrorMethod, "libfptr_reset_error", 1);

    FIND_FUNC(SET_PARAM_BOOL_METHOD, m_setParamBoolMethod, "libfptr_set_param_bool", 1);
    FIND_FUNC(SET_PARAM_INT_METHOD, m_setParamIntMethod, "libfptr_set_param_int", 1);
    FIND_FUNC(SET_PARAM_DOUBLE_METHOD, m_setParamDoubleMethod, "libfptr_set_param_double", 1);
    FIND_FUNC(SET_PARAM_STRING_METHOD, m_setParamStringMethod, "libfptr_set_param_str", 1);
    FIND_FUNC(SET_PARAM_BYTEARRAY_METHOD, m_setParamByteArrayMethod, "libfptr_set_param_bytearray", 1);
    FIND_FUNC(SET_PARAM_DATETIME_METHOD, m_setParamDateTimeMethod, "libfptr_set_param_datetime", 1);

    FIND_FUNC(SET_PARAM_BOOL_METHOD, m_setNonPrintableParamBoolMethod, "libfptr_set_non_printable_param_bool", 1);
    FIND_FUNC(SET_PARAM_INT_METHOD, m_setNonPrintableParamIntMethod, "libfptr_set_non_printable_param_int", 1);
    FIND_FUNC(SET_PARAM_DOUBLE_METHOD, m_setNonPrintableParamDoubleMethod, "libfptr_set_non_printable_param_double", 1);
    FIND_FUNC(SET_PARAM_STRING_METHOD, m_setNonPrintableParamStringMethod, "libfptr_set_non_printable_param_str", 1);
    FIND_FUNC(SET_PARAM_BYTEARRAY_METHOD, m_setNonPrintableParamByteArrayMethod, "libfptr_set_non_printable_param_bytearray", 1);
    FIND_FUNC(SET_PARAM_DATETIME_METHOD, m_setNonPrintableParamDateTimeMethod, "libfptr_set_non_printable_param_datetime", 1);

    FIND_FUNC(SET_PARAM_BOOL_METHOD, m_setUserParamBoolMethod, "libfptr_set_user_param_bool", 1);
    FIND_FUNC(SET_PARAM_INT_METHOD, m_setUserParamIntMethod, "libfptr_set_user_param_int", 1);
    FIND_FUNC(SET_PARAM_DOUBLE_METHOD, m_setUserParamDoubleMethod, "libfptr_set_user_param_double", 1);
    FIND_FUNC(SET_PARAM_STRING_METHOD, m_setUserParamStringMethod, "libfptr_set_user_param_str", 1);
    FIND_FUNC(SET_PARAM_BYTEARRAY_METHOD, m_setUserParamByteArrayMethod, "libfptr_set_user_param_bytearray", 1);
    FIND_FUNC(SET_PARAM_DATETIME_METHOD, m_setUserParamDateTimeMethod, "libfptr_set_user_param_datetime", 1);

    FIND_FUNC(GET_PARAM_BOOL_METHOD, m_getParamBoolMethod, "libfptr_get_param_bool", 1);
    FIND_FUNC(GET_PARAM_INT_METHOD, m_getParamIntMethod, "libfptr_get_param_int", 1);
    FIND_FUNC(GET_PARAM_DOUBLE_METHOD, m_getParamDoubleMethod, "libfptr_get_param_double", 1);
    FIND_FUNC(GET_PARAM_STRING_METHOD, m_getParamStringMethod, "libfptr_get_param_str", 1);
    FIND_FUNC(GET_PARAM_BYTEARRAY_METHOD, m_getParamByteArrayMethod, "libfptr_get_param_bytearray", 1);
    FIND_FUNC(GET_PARAM_DATETIME_METHOD, m_getParamDateTimeMethod, "libfptr_get_param_datetime", 1);

    FIND_FUNC(WRITE_LOG_METHOD, m_writeLogMethod, "libfptr_log_write", 1);

    FIND_FUNC(SHOW_PROPERTIES_METHOD, m_showPropertiesMethod, "libfptr_show_properties", 1);

    
    FIND_FUNC(COMMON_METHOD, m_applySingleSettingsMethod, "libfptr_apply_single_settings", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_openMethod, "libfptr_open", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_closeMethod, "libfptr_close", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_resetParamsMethod, "libfptr_reset_params", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_runCommandMethod, "libfptr_run_command", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_beepMethod, "libfptr_beep", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_openDrawerMethod, "libfptr_open_drawer", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_cutMethod, "libfptr_cut", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_devicePoweroffMethod, "libfptr_device_poweroff", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_deviceRebootMethod, "libfptr_device_reboot", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_openShiftMethod, "libfptr_open_shift", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_resetSummaryMethod, "libfptr_reset_summary", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_initDeviceMethod, "libfptr_init_device", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_queryDataMethod, "libfptr_query_data", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_cashIncomeMethod, "libfptr_cash_income", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_cashOutcomeMethod, "libfptr_cash_outcome", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_openReceiptMethod, "libfptr_open_receipt", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_cancelReceiptMethod, "libfptr_cancel_receipt", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_closeReceiptMethod, "libfptr_close_receipt", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_checkDocumentClosedMethod, "libfptr_check_document_closed", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_receiptTotalMethod, "libfptr_receipt_total", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_receiptTaxMethod, "libfptr_receipt_tax", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_registrationMethod, "libfptr_registration", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_paymentMethod, "libfptr_payment", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_reportMethod, "libfptr_report", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_printTextMethod, "libfptr_print_text", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_printClicheMethod, "libfptr_print_cliche", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_beginNonfiscalDocumentMethod, "libfptr_begin_nonfiscal_document", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_endNonfiscalDocumentMethod, "libfptr_end_nonfiscal_document", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_printBarcodeMethod, "libfptr_print_barcode", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_printPictureMethod, "libfptr_print_picture", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_printPictureByNumberMethod, "libfptr_print_picture_by_number", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_uploadPictureFromFileMethod, "libfptr_upload_picture_from_file", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_clearPicturesMethod, "libfptr_clear_pictures", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_writeDeviceSettingRawMethod, "libfptr_write_device_setting_raw", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_readDeviceSettingRawMethod, "libfptr_read_device_setting_raw", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_commitSettingsMethod, "libfptr_commit_settings", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_initSettingsMethod, "libfptr_init_settings", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_resetSettingsMethod, "libfptr_reset_settings", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_writeDateTimeMethod, "libfptr_write_date_time", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_writeLicenseMethod, "libfptr_write_license", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_fnOperationMethod, "libfptr_fn_operation", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_fnQueryDataMethod, "libfptr_fn_query_data", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_fnWriteAttributesMethod, "libfptr_fn_write_attributes", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_externalDevicePowerOnMethod, "libfptr_external_device_power_on", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_externalDevicePowerOffMethod, "libfptr_external_device_power_off", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_externalDeviceWriteDataMethod, "libfptr_external_device_write_data", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_externalDeviceReadDataMethod, "libfptr_external_device_read_data", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_operatorLoginMethod, "libfptr_operator_login", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_processJsonMethod, "libfptr_process_json", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_readDeviceSettingMethod, "libfptr_read_device_setting", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_writeDeviceSettingMethod, "libfptr_write_device_setting", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_beginReadRecordsMethod, "libfptr_begin_read_records", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_readNextRecordMethod, "libfptr_read_next_record", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_endReadRecordsMethod, "libfptr_end_read_records", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_userMemoryOperationMethod, "libfptr_user_memory_operation", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_continuePrintMethod, "libfptr_continue_print", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_initMgmMethod, "libfptr_init_mgm", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_utilFormTlvMethod, "libfptr_util_form_tlv", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_utilFormNomenclatureMethod, "libfptr_util_form_nomenclature", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_utilMappingMethod, "libfptr_util_mapping", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_readModelFlagsMethod, "libfptr_read_model_flags", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_lineFeedMethod, "libfptr_line_feed", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_flashFirmwareMethod, "libfptr_flash_firmware", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_softLockInitMethod, "libfptr_soft_lock_init", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_softLockQuerySessionCodeMethod, "libfptr_soft_lock_query_session_code", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_softLockValidateMethod, "libfptr_soft_lock_validate", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_utilCalcTaxMethod, "libfptr_util_calc_tax", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_downloadPictureMethod, "libfptr_download_picture", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_bluetoothRemovePairedDevicesMethod, "libfptr_bluetooth_remove_paired_devices", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_utilTagInfoMethod, "libfptr_util_tag_info", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_utilContainerVersionsMethod, "libfptr_util_container_versions", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_activateLicensesMethod, "libfptr_activate_licenses", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_removeLicensesMethod, "libfptr_remove_licenses", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_enterKeysMethod, "libfptr_enter_keys", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_validateKeysMethod, "libfptr_validate_keys", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_enterSerialNumberMethod, "libfptr_enter_serial_number", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_getSerialNumberRequestMethod, "libfptr_get_serial_number_request", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_uploadPixelBufferMethod, "libfptr_upload_pixel_buffer", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_downloadPixelBufferMethod, "libfptr_download_pixel_buffer", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_printPixelBufferMethod, "libfptr_print_pixel_buffer", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_utilConvertTagValueMethod, "libfptr_util_convert_tag_value", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_parseMarkingCodeMethod, "libfptr_parse_marking_code", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_callScriptMethod, "libfptr_call_script", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_setHeaderLinesMethod, "libfptr_set_header_lines", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_setFooterLinesMethod, "libfptr_set_footer_lines", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_uploadPictureClicheMethod, "libfptr_upload_picture_cliche", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_uploadPictureMemoryMethod, "libfptr_upload_picture_memory", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_uploadPixelBufferClicheMethod, "libfptr_upload_pixel_buffer_cliche", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_uploadPixelBufferMemoryMethod, "libfptr_upload_pixel_buffer_memory", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_execDriverScriptMethod, "libfptr_exec_driver_script", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_uploadDriverScriptMethod, "libfptr_upload_driver_script", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_execDriverScriptByIdMethod, "libfptr_exec_driver_script_by_id", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_writeUniversalCountersSettingsMethod, "libfptr_write_universal_counters_settings", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_readUniversalCountersSettingsMethod, "libfptr_read_universal_counters_settings", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_queryUniversalCountersStateMethod, "libfptr_query_universal_counters_state", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_resetUniversalCountersMethod, "libfptr_reset_universal_counters", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_cacheUniversalCountersMethod, "libfptr_cache_universal_counters", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_readUniversalCounterSumMethod, "libfptr_read_universal_counter_sum", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_readUniversalCounterQuantityMethod, "libfptr_read_universal_counter_quantity", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_clearUniversalCountersCacheMethod, "libfptr_clear_universal_counters_cache", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_disableOfdChannelMethod, "libfptr_disable_ofd_channel", DTOX_ERROR_ON_METHOD_LOAD);

    FIND_FUNC(COMMON_METHOD, m_enableOfdChannelMethod, "libfptr_enable_ofd_channel", DTOX_ERROR_ON_METHOD_LOAD);

}

Fptr::~Fptr()
{
    if (m_fptr)
        m_destroyMethod(&m_fptr);
}

std::string Fptr::version()
{
    return m_getVersionMethod();
}

int Fptr::logWrite(const std::wstring &tag, int level, const std::wstring &message)
{
    return m_writeLogMethod(tag.c_str(), level, message.c_str());
}

bool Fptr::isOpened()
{
    return m_isOpenedMethod(m_fptr) != 0;
}

int Fptr::showProperties(int parantType, void *parent)
{
    return m_showPropertiesMethod(m_fptr, parantType, parent);
}

int Fptr::errorCode()
{
    return m_errorCodeMethod(m_fptr);
}

std::wstring Fptr::errorDescription()
{
    std::vector<wchar_t> description(128);
    int size = m_errorDescriptionMethod(m_fptr, &description[0], description.size());
    if (size > description.size())
    {
        description.resize(size, 0x00);
        m_errorDescriptionMethod(m_fptr, &description[0], description.size());
    }

    return &description[0];
}

void Fptr::resetError()
{
    return m_resetErrorMethod(m_fptr);
}

int Fptr::setSettings(const std::wstring &settings)
{
    return m_setSettingsMethod(m_fptr, settings.c_str());
}

std::wstring Fptr::getSettings()
{
    std::vector<wchar_t> settings(128);
    int size = m_getSettingsMethod(m_fptr, &settings[0], settings.size());
    if (size > settings.size())
    {
        settings.resize(size, 0x00);
        m_getSettingsMethod(m_fptr, &settings[0], settings.size());
    }

    return &settings[0];
}

void Fptr::setSingleSetting(const std::wstring &key, const std::wstring &value)
{
    return m_setSingleSettingMethod(m_fptr, key.c_str(), value.c_str());
}

std::wstring Fptr::getSingleSetting(const std::wstring &key)
{
    std::vector<wchar_t> setting(16);
    int size = m_getSingleSettingMethod(m_fptr, key.c_str(), &setting[0], setting.size());
    if (size > setting.size())
    {
        setting.resize(size, 0x00);
        m_getSingleSettingMethod(m_fptr, key.c_str(), &setting[0], setting.size());
    }

    return &setting[0];
}

void Fptr::setParam(int param, int value)
{
    m_setParamIntMethod(m_fptr, param, value);
}

void Fptr::setParam(int param, unsigned int value)
{
    m_setParamIntMethod(m_fptr, param, value);
}

void Fptr::setParam(int param, bool value)
{
    m_setParamBoolMethod(m_fptr, param, value ? 1 : 0);
}

void Fptr::setParam(int param, double value)
{
    m_setParamDoubleMethod(m_fptr, param, value);
}

void Fptr::setParam(int param, const std::wstring &value)
{
    m_setParamStringMethod(m_fptr, param, value.c_str());
}

void Fptr::setParam(int param, const wchar_t *value)
{
    m_setParamStringMethod(m_fptr, param, value);
}

void Fptr::setParam(int param, unsigned char *value, int size)
{
    m_setParamByteArrayMethod(m_fptr, param, value, size);
}

void Fptr::setParam(int param, const std::tm &value)
{
    m_setParamDateTimeMethod(m_fptr, param,
                             value.tm_year + 1900, value.tm_mon + 1, value.tm_mday,
                             value.tm_hour, value.tm_min, value.tm_sec);
}

void Fptr::setNonPrintableParam(int param, int value)
{
    m_setNonPrintableParamIntMethod(m_fptr, param, value);
}

void Fptr::setNonPrintableParam(int param, unsigned int value)
{
    m_setNonPrintableParamIntMethod(m_fptr, param, value);
}

void Fptr::setNonPrintableParam(int param, bool value)
{
    m_setNonPrintableParamBoolMethod(m_fptr, param, value ? 1 : 0);
}

void Fptr::setNonPrintableParam(int param, double value)
{
    m_setNonPrintableParamDoubleMethod(m_fptr, param, value);
}

void Fptr::setNonPrintableParam(int param, const std::wstring &value)
{
    m_setNonPrintableParamStringMethod(m_fptr, param, value.c_str());
}

void Fptr::setNonPrintableParam(int param, const unsigned char *value, int size)
{
    m_setNonPrintableParamByteArrayMethod(m_fptr, param, value, size);
}

void Fptr::setNonPrintableParam(int param, const std::tm &value)
{
    m_setNonPrintableParamDateTimeMethod(m_fptr, param,
                                         value.tm_year + 1900, value.tm_mon + 1, value.tm_mday,
                                         value.tm_hour, value.tm_min, value.tm_sec);
}

void Fptr::setUserParam(int param, int value)
{
    m_setUserParamIntMethod(m_fptr, param, value);
}

void Fptr::setUserParam(int param, unsigned int value)
{
    m_setUserParamIntMethod(m_fptr, param, value);
}

void Fptr::setUserParam(int param, bool value)
{
    m_setUserParamBoolMethod(m_fptr, param, value ? 1 : 0);
}

void Fptr::setUserParam(int param, double value)
{
    m_setUserParamDoubleMethod(m_fptr, param, value);
}

void Fptr::setUserParam(int param, const std::wstring &value)
{
    m_setUserParamStringMethod(m_fptr, param, value.c_str());
}

void Fptr::setUserParam(int param, unsigned char *value, int size)
{
    m_setUserParamByteArrayMethod(m_fptr, param, value, size);
}

void Fptr::setUserParam(int param, const std::tm &value)
{
    m_setUserParamDateTimeMethod(m_fptr, param,
                                 value.tm_year + 1900, value.tm_mon + 1, value.tm_mday,
                                 value.tm_hour, value.tm_min, value.tm_sec);
}

unsigned int Fptr::getParamInt(int param)
{
    return m_getParamIntMethod(m_fptr, param);
}

bool Fptr::getParamBool(int param)
{
    return m_getParamBoolMethod(m_fptr, param) != 0;
}

double Fptr::getParamDouble(int param)
{
    return m_getParamDoubleMethod(m_fptr, param);
}

std::wstring Fptr::getParamString(int param)
{
    std::vector<wchar_t> value(256);
    int size = m_getParamStringMethod(m_fptr, param, &value[0], value.size());
    if (size > value.size())
    {
        value.resize(size, 0x00);
        m_getParamStringMethod(m_fptr, param, &value[0], value.size());
    }

    return &value[0];
}

std::vector<unsigned char> Fptr::getParamByteArray(int param)
{
    std::vector<unsigned char> value(256);
    int size = m_getParamByteArrayMethod(m_fptr, param, &value[0], value.size());
    if (size > value.size())
    {
        value.resize(size);
        size = m_getParamByteArrayMethod(m_fptr, param, &value[0], value.size());
    }
    value.resize(size);

    return value;
}

int Fptr::getParamByteArray(int param, unsigned char *value, int size)
{
    return m_getParamByteArrayMethod(m_fptr, param, value, size);
}

std::tm Fptr::getParamDateTime(int param)
{
    std::tm t = {};
    m_getParamDateTimeMethod(m_fptr, param,
                             &t.tm_year,
                             &t.tm_mon,
                             &t.tm_mday,
                             &t.tm_hour,
                             &t.tm_min,
                             &t.tm_sec);
    t.tm_year -= 1900;
    t.tm_mon -= 1;
    return t;
}


int Fptr::applySingleSettings()
{
    if (!m_applySingleSettingsMethod)
        throw std::logic_error("method libfptr_apply_single_settings() not found");

    return m_applySingleSettingsMethod(m_fptr);
}

int Fptr::open()
{
    if (!m_openMethod)
        throw std::logic_error("method libfptr_open() not found");

    return m_openMethod(m_fptr);
}

int Fptr::close()
{
    if (!m_closeMethod)
        throw std::logic_error("method libfptr_close() not found");

    return m_closeMethod(m_fptr);
}

int Fptr::resetParams()
{
    if (!m_resetParamsMethod)
        throw std::logic_error("method libfptr_reset_params() not found");

    return m_resetParamsMethod(m_fptr);
}

int Fptr::runCommand()
{
    if (!m_runCommandMethod)
        throw std::logic_error("method libfptr_run_command() not found");

    return m_runCommandMethod(m_fptr);
}

int Fptr::beep()
{
    if (!m_beepMethod)
        throw std::logic_error("method libfptr_beep() not found");

    return m_beepMethod(m_fptr);
}

int Fptr::openDrawer()
{
    if (!m_openDrawerMethod)
        throw std::logic_error("method libfptr_open_drawer() not found");

    return m_openDrawerMethod(m_fptr);
}

int Fptr::cut()
{
    if (!m_cutMethod)
        throw std::logic_error("method libfptr_cut() not found");

    return m_cutMethod(m_fptr);
}

int Fptr::devicePoweroff()
{
    if (!m_devicePoweroffMethod)
        throw std::logic_error("method libfptr_device_poweroff() not found");

    return m_devicePoweroffMethod(m_fptr);
}

int Fptr::deviceReboot()
{
    if (!m_deviceRebootMethod)
        throw std::logic_error("method libfptr_device_reboot() not found");

    return m_deviceRebootMethod(m_fptr);
}

int Fptr::openShift()
{
    if (!m_openShiftMethod)
        throw std::logic_error("method libfptr_open_shift() not found");

    return m_openShiftMethod(m_fptr);
}

int Fptr::resetSummary()
{
    if (!m_resetSummaryMethod)
        throw std::logic_error("method libfptr_reset_summary() not found");

    return m_resetSummaryMethod(m_fptr);
}

int Fptr::initDevice()
{
    if (!m_initDeviceMethod)
        throw std::logic_error("method libfptr_init_device() not found");

    return m_initDeviceMethod(m_fptr);
}

int Fptr::queryData()
{
    if (!m_queryDataMethod)
        throw std::logic_error("method libfptr_query_data() not found");

    return m_queryDataMethod(m_fptr);
}

int Fptr::cashIncome()
{
    if (!m_cashIncomeMethod)
        throw std::logic_error("method libfptr_cash_income() not found");

    return m_cashIncomeMethod(m_fptr);
}

int Fptr::cashOutcome()
{
    if (!m_cashOutcomeMethod)
        throw std::logic_error("method libfptr_cash_outcome() not found");

    return m_cashOutcomeMethod(m_fptr);
}

int Fptr::openReceipt()
{
    if (!m_openReceiptMethod)
        throw std::logic_error("method libfptr_open_receipt() not found");

    return m_openReceiptMethod(m_fptr);
}

int Fptr::cancelReceipt()
{
    if (!m_cancelReceiptMethod)
        throw std::logic_error("method libfptr_cancel_receipt() not found");

    return m_cancelReceiptMethod(m_fptr);
}

int Fptr::closeReceipt()
{
    if (!m_closeReceiptMethod)
        throw std::logic_error("method libfptr_close_receipt() not found");

    return m_closeReceiptMethod(m_fptr);
}

int Fptr::checkDocumentClosed()
{
    if (!m_checkDocumentClosedMethod)
        throw std::logic_error("method libfptr_check_document_closed() not found");

    return m_checkDocumentClosedMethod(m_fptr);
}

int Fptr::receiptTotal()
{
    if (!m_receiptTotalMethod)
        throw std::logic_error("method libfptr_receipt_total() not found");

    return m_receiptTotalMethod(m_fptr);
}

int Fptr::receiptTax()
{
    if (!m_receiptTaxMethod)
        throw std::logic_error("method libfptr_receipt_tax() not found");

    return m_receiptTaxMethod(m_fptr);
}

int Fptr::registration()
{
    if (!m_registrationMethod)
        throw std::logic_error("method libfptr_registration() not found");

    return m_registrationMethod(m_fptr);
}

int Fptr::payment()
{
    if (!m_paymentMethod)
        throw std::logic_error("method libfptr_payment() not found");

    return m_paymentMethod(m_fptr);
}

int Fptr::report()
{
    if (!m_reportMethod)
        throw std::logic_error("method libfptr_report() not found");

    return m_reportMethod(m_fptr);
}

int Fptr::printText()
{
    if (!m_printTextMethod)
        throw std::logic_error("method libfptr_print_text() not found");

    return m_printTextMethod(m_fptr);
}

int Fptr::printCliche()
{
    if (!m_printClicheMethod)
        throw std::logic_error("method libfptr_print_cliche() not found");

    return m_printClicheMethod(m_fptr);
}

int Fptr::beginNonfiscalDocument()
{
    if (!m_beginNonfiscalDocumentMethod)
        throw std::logic_error("method libfptr_begin_nonfiscal_document() not found");

    return m_beginNonfiscalDocumentMethod(m_fptr);
}

int Fptr::endNonfiscalDocument()
{
    if (!m_endNonfiscalDocumentMethod)
        throw std::logic_error("method libfptr_end_nonfiscal_document() not found");

    return m_endNonfiscalDocumentMethod(m_fptr);
}

int Fptr::printBarcode()
{
    if (!m_printBarcodeMethod)
        throw std::logic_error("method libfptr_print_barcode() not found");

    return m_printBarcodeMethod(m_fptr);
}

int Fptr::printPicture()
{
    if (!m_printPictureMethod)
        throw std::logic_error("method libfptr_print_picture() not found");

    return m_printPictureMethod(m_fptr);
}

int Fptr::printPictureByNumber()
{
    if (!m_printPictureByNumberMethod)
        throw std::logic_error("method libfptr_print_picture_by_number() not found");

    return m_printPictureByNumberMethod(m_fptr);
}

int Fptr::uploadPictureFromFile()
{
    if (!m_uploadPictureFromFileMethod)
        throw std::logic_error("method libfptr_upload_picture_from_file() not found");

    return m_uploadPictureFromFileMethod(m_fptr);
}

int Fptr::clearPictures()
{
    if (!m_clearPicturesMethod)
        throw std::logic_error("method libfptr_clear_pictures() not found");

    return m_clearPicturesMethod(m_fptr);
}

int Fptr::writeDeviceSettingRaw()
{
    if (!m_writeDeviceSettingRawMethod)
        throw std::logic_error("method libfptr_write_device_setting_raw() not found");

    return m_writeDeviceSettingRawMethod(m_fptr);
}

int Fptr::readDeviceSettingRaw()
{
    if (!m_readDeviceSettingRawMethod)
        throw std::logic_error("method libfptr_read_device_setting_raw() not found");

    return m_readDeviceSettingRawMethod(m_fptr);
}

int Fptr::commitSettings()
{
    if (!m_commitSettingsMethod)
        throw std::logic_error("method libfptr_commit_settings() not found");

    return m_commitSettingsMethod(m_fptr);
}

int Fptr::initSettings()
{
    if (!m_initSettingsMethod)
        throw std::logic_error("method libfptr_init_settings() not found");

    return m_initSettingsMethod(m_fptr);
}

int Fptr::resetSettings()
{
    if (!m_resetSettingsMethod)
        throw std::logic_error("method libfptr_reset_settings() not found");

    return m_resetSettingsMethod(m_fptr);
}

int Fptr::writeDateTime()
{
    if (!m_writeDateTimeMethod)
        throw std::logic_error("method libfptr_write_date_time() not found");

    return m_writeDateTimeMethod(m_fptr);
}

int Fptr::writeLicense()
{
    if (!m_writeLicenseMethod)
        throw std::logic_error("method libfptr_write_license() not found");

    return m_writeLicenseMethod(m_fptr);
}

int Fptr::fnOperation()
{
    if (!m_fnOperationMethod)
        throw std::logic_error("method libfptr_fn_operation() not found");

    return m_fnOperationMethod(m_fptr);
}

int Fptr::fnQueryData()
{
    if (!m_fnQueryDataMethod)
        throw std::logic_error("method libfptr_fn_query_data() not found");

    return m_fnQueryDataMethod(m_fptr);
}

int Fptr::fnWriteAttributes()
{
    if (!m_fnWriteAttributesMethod)
        throw std::logic_error("method libfptr_fn_write_attributes() not found");

    return m_fnWriteAttributesMethod(m_fptr);
}

int Fptr::externalDevicePowerOn()
{
    if (!m_externalDevicePowerOnMethod)
        throw std::logic_error("method libfptr_external_device_power_on() not found");

    return m_externalDevicePowerOnMethod(m_fptr);
}

int Fptr::externalDevicePowerOff()
{
    if (!m_externalDevicePowerOffMethod)
        throw std::logic_error("method libfptr_external_device_power_off() not found");

    return m_externalDevicePowerOffMethod(m_fptr);
}

int Fptr::externalDeviceWriteData()
{
    if (!m_externalDeviceWriteDataMethod)
        throw std::logic_error("method libfptr_external_device_write_data() not found");

    return m_externalDeviceWriteDataMethod(m_fptr);
}

int Fptr::externalDeviceReadData()
{
    if (!m_externalDeviceReadDataMethod)
        throw std::logic_error("method libfptr_external_device_read_data() not found");

    return m_externalDeviceReadDataMethod(m_fptr);
}

int Fptr::operatorLogin()
{
    if (!m_operatorLoginMethod)
        throw std::logic_error("method libfptr_operator_login() not found");

    return m_operatorLoginMethod(m_fptr);
}

int Fptr::processJson()
{
    if (!m_processJsonMethod)
        throw std::logic_error("method libfptr_process_json() not found");

    return m_processJsonMethod(m_fptr);
}

int Fptr::readDeviceSetting()
{
    if (!m_readDeviceSettingMethod)
        throw std::logic_error("method libfptr_read_device_setting() not found");

    return m_readDeviceSettingMethod(m_fptr);
}

int Fptr::writeDeviceSetting()
{
    if (!m_writeDeviceSettingMethod)
        throw std::logic_error("method libfptr_write_device_setting() not found");

    return m_writeDeviceSettingMethod(m_fptr);
}

int Fptr::beginReadRecords()
{
    if (!m_beginReadRecordsMethod)
        throw std::logic_error("method libfptr_begin_read_records() not found");

    return m_beginReadRecordsMethod(m_fptr);
}

int Fptr::readNextRecord()
{
    if (!m_readNextRecordMethod)
        throw std::logic_error("method libfptr_read_next_record() not found");

    return m_readNextRecordMethod(m_fptr);
}

int Fptr::endReadRecords()
{
    if (!m_endReadRecordsMethod)
        throw std::logic_error("method libfptr_end_read_records() not found");

    return m_endReadRecordsMethod(m_fptr);
}

int Fptr::userMemoryOperation()
{
    if (!m_userMemoryOperationMethod)
        throw std::logic_error("method libfptr_user_memory_operation() not found");

    return m_userMemoryOperationMethod(m_fptr);
}

int Fptr::continuePrint()
{
    if (!m_continuePrintMethod)
        throw std::logic_error("method libfptr_continue_print() not found");

    return m_continuePrintMethod(m_fptr);
}

int Fptr::initMgm()
{
    if (!m_initMgmMethod)
        throw std::logic_error("method libfptr_init_mgm() not found");

    return m_initMgmMethod(m_fptr);
}

int Fptr::utilFormTlv()
{
    if (!m_utilFormTlvMethod)
        throw std::logic_error("method libfptr_util_form_tlv() not found");

    return m_utilFormTlvMethod(m_fptr);
}

int Fptr::utilFormNomenclature()
{
    if (!m_utilFormNomenclatureMethod)
        throw std::logic_error("method libfptr_util_form_nomenclature() not found");

    return m_utilFormNomenclatureMethod(m_fptr);
}

int Fptr::utilMapping()
{
    if (!m_utilMappingMethod)
        throw std::logic_error("method libfptr_util_mapping() not found");

    return m_utilMappingMethod(m_fptr);
}

int Fptr::readModelFlags()
{
    if (!m_readModelFlagsMethod)
        throw std::logic_error("method libfptr_read_model_flags() not found");

    return m_readModelFlagsMethod(m_fptr);
}

int Fptr::lineFeed()
{
    if (!m_lineFeedMethod)
        throw std::logic_error("method libfptr_line_feed() not found");

    return m_lineFeedMethod(m_fptr);
}

int Fptr::flashFirmware()
{
    if (!m_flashFirmwareMethod)
        throw std::logic_error("method libfptr_flash_firmware() not found");

    return m_flashFirmwareMethod(m_fptr);
}

int Fptr::softLockInit()
{
    if (!m_softLockInitMethod)
        throw std::logic_error("method libfptr_soft_lock_init() not found");

    return m_softLockInitMethod(m_fptr);
}

int Fptr::softLockQuerySessionCode()
{
    if (!m_softLockQuerySessionCodeMethod)
        throw std::logic_error("method libfptr_soft_lock_query_session_code() not found");

    return m_softLockQuerySessionCodeMethod(m_fptr);
}

int Fptr::softLockValidate()
{
    if (!m_softLockValidateMethod)
        throw std::logic_error("method libfptr_soft_lock_validate() not found");

    return m_softLockValidateMethod(m_fptr);
}

int Fptr::utilCalcTax()
{
    if (!m_utilCalcTaxMethod)
        throw std::logic_error("method libfptr_util_calc_tax() not found");

    return m_utilCalcTaxMethod(m_fptr);
}

int Fptr::downloadPicture()
{
    if (!m_downloadPictureMethod)
        throw std::logic_error("method libfptr_download_picture() not found");

    return m_downloadPictureMethod(m_fptr);
}

int Fptr::bluetoothRemovePairedDevices()
{
    if (!m_bluetoothRemovePairedDevicesMethod)
        throw std::logic_error("method libfptr_bluetooth_remove_paired_devices() not found");

    return m_bluetoothRemovePairedDevicesMethod(m_fptr);
}

int Fptr::utilTagInfo()
{
    if (!m_utilTagInfoMethod)
        throw std::logic_error("method libfptr_util_tag_info() not found");

    return m_utilTagInfoMethod(m_fptr);
}

int Fptr::utilContainerVersions()
{
    if (!m_utilContainerVersionsMethod)
        throw std::logic_error("method libfptr_util_container_versions() not found");

    return m_utilContainerVersionsMethod(m_fptr);
}

int Fptr::activateLicenses()
{
    if (!m_activateLicensesMethod)
        throw std::logic_error("method libfptr_activate_licenses() not found");

    return m_activateLicensesMethod(m_fptr);
}

int Fptr::removeLicenses()
{
    if (!m_removeLicensesMethod)
        throw std::logic_error("method libfptr_remove_licenses() not found");

    return m_removeLicensesMethod(m_fptr);
}

int Fptr::enterKeys()
{
    if (!m_enterKeysMethod)
        throw std::logic_error("method libfptr_enter_keys() not found");

    return m_enterKeysMethod(m_fptr);
}

int Fptr::validateKeys()
{
    if (!m_validateKeysMethod)
        throw std::logic_error("method libfptr_validate_keys() not found");

    return m_validateKeysMethod(m_fptr);
}

int Fptr::enterSerialNumber()
{
    if (!m_enterSerialNumberMethod)
        throw std::logic_error("method libfptr_enter_serial_number() not found");

    return m_enterSerialNumberMethod(m_fptr);
}

int Fptr::getSerialNumberRequest()
{
    if (!m_getSerialNumberRequestMethod)
        throw std::logic_error("method libfptr_get_serial_number_request() not found");

    return m_getSerialNumberRequestMethod(m_fptr);
}

int Fptr::uploadPixelBuffer()
{
    if (!m_uploadPixelBufferMethod)
        throw std::logic_error("method libfptr_upload_pixel_buffer() not found");

    return m_uploadPixelBufferMethod(m_fptr);
}

int Fptr::downloadPixelBuffer()
{
    if (!m_downloadPixelBufferMethod)
        throw std::logic_error("method libfptr_download_pixel_buffer() not found");

    return m_downloadPixelBufferMethod(m_fptr);
}

int Fptr::printPixelBuffer()
{
    if (!m_printPixelBufferMethod)
        throw std::logic_error("method libfptr_print_pixel_buffer() not found");

    return m_printPixelBufferMethod(m_fptr);
}

int Fptr::utilConvertTagValue()
{
    if (!m_utilConvertTagValueMethod)
        throw std::logic_error("method libfptr_util_convert_tag_value() not found");

    return m_utilConvertTagValueMethod(m_fptr);
}

int Fptr::parseMarkingCode()
{
    if (!m_parseMarkingCodeMethod)
        throw std::logic_error("method libfptr_parse_marking_code() not found");

    return m_parseMarkingCodeMethod(m_fptr);
}

int Fptr::callScript()
{
    if (!m_callScriptMethod)
        throw std::logic_error("method libfptr_call_script() not found");

    return m_callScriptMethod(m_fptr);
}

int Fptr::setHeaderLines()
{
    if (!m_setHeaderLinesMethod)
        throw std::logic_error("method libfptr_set_header_lines() not found");

    return m_setHeaderLinesMethod(m_fptr);
}

int Fptr::setFooterLines()
{
    if (!m_setFooterLinesMethod)
        throw std::logic_error("method libfptr_set_footer_lines() not found");

    return m_setFooterLinesMethod(m_fptr);
}

int Fptr::uploadPictureCliche()
{
    if (!m_uploadPictureClicheMethod)
        throw std::logic_error("method libfptr_upload_picture_cliche() not found");

    return m_uploadPictureClicheMethod(m_fptr);
}

int Fptr::uploadPictureMemory()
{
    if (!m_uploadPictureMemoryMethod)
        throw std::logic_error("method libfptr_upload_picture_memory() not found");

    return m_uploadPictureMemoryMethod(m_fptr);
}

int Fptr::uploadPixelBufferCliche()
{
    if (!m_uploadPixelBufferClicheMethod)
        throw std::logic_error("method libfptr_upload_pixel_buffer_cliche() not found");

    return m_uploadPixelBufferClicheMethod(m_fptr);
}

int Fptr::uploadPixelBufferMemory()
{
    if (!m_uploadPixelBufferMemoryMethod)
        throw std::logic_error("method libfptr_upload_pixel_buffer_memory() not found");

    return m_uploadPixelBufferMemoryMethod(m_fptr);
}

int Fptr::execDriverScript()
{
    if (!m_execDriverScriptMethod)
        throw std::logic_error("method libfptr_exec_driver_script() not found");

    return m_execDriverScriptMethod(m_fptr);
}

int Fptr::uploadDriverScript()
{
    if (!m_uploadDriverScriptMethod)
        throw std::logic_error("method libfptr_upload_driver_script() not found");

    return m_uploadDriverScriptMethod(m_fptr);
}

int Fptr::execDriverScriptById()
{
    if (!m_execDriverScriptByIdMethod)
        throw std::logic_error("method libfptr_exec_driver_script_by_id() not found");

    return m_execDriverScriptByIdMethod(m_fptr);
}

int Fptr::writeUniversalCountersSettings()
{
    if (!m_writeUniversalCountersSettingsMethod)
        throw std::logic_error("method libfptr_write_universal_counters_settings() not found");

    return m_writeUniversalCountersSettingsMethod(m_fptr);
}

int Fptr::readUniversalCountersSettings()
{
    if (!m_readUniversalCountersSettingsMethod)
        throw std::logic_error("method libfptr_read_universal_counters_settings() not found");

    return m_readUniversalCountersSettingsMethod(m_fptr);
}

int Fptr::queryUniversalCountersState()
{
    if (!m_queryUniversalCountersStateMethod)
        throw std::logic_error("method libfptr_query_universal_counters_state() not found");

    return m_queryUniversalCountersStateMethod(m_fptr);
}

int Fptr::resetUniversalCounters()
{
    if (!m_resetUniversalCountersMethod)
        throw std::logic_error("method libfptr_reset_universal_counters() not found");

    return m_resetUniversalCountersMethod(m_fptr);
}

int Fptr::cacheUniversalCounters()
{
    if (!m_cacheUniversalCountersMethod)
        throw std::logic_error("method libfptr_cache_universal_counters() not found");

    return m_cacheUniversalCountersMethod(m_fptr);
}

int Fptr::readUniversalCounterSum()
{
    if (!m_readUniversalCounterSumMethod)
        throw std::logic_error("method libfptr_read_universal_counter_sum() not found");

    return m_readUniversalCounterSumMethod(m_fptr);
}

int Fptr::readUniversalCounterQuantity()
{
    if (!m_readUniversalCounterQuantityMethod)
        throw std::logic_error("method libfptr_read_universal_counter_quantity() not found");

    return m_readUniversalCounterQuantityMethod(m_fptr);
}

int Fptr::clearUniversalCountersCache()
{
    if (!m_clearUniversalCountersCacheMethod)
        throw std::logic_error("method libfptr_clear_universal_counters_cache() not found");

    return m_clearUniversalCountersCacheMethod(m_fptr);
}

int Fptr::disableOfdChannel()
{
    if (!m_disableOfdChannelMethod)
        throw std::logic_error("method libfptr_disable_ofd_channel() not found");

    return m_disableOfdChannelMethod(m_fptr);
}

int Fptr::enableOfdChannel()
{
    if (!m_enableOfdChannelMethod)
        throw std::logic_error("method libfptr_enable_ofd_channel() not found");

    return m_enableOfdChannelMethod(m_fptr);
}


}
}
