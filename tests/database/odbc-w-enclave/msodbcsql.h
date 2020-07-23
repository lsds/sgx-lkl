#ifndef __msodbcsql_h__
#define __msodbcsql_h__

/*
 *-----------------------------------------------------------------------------
 * File:        msodbcsql.h
 *
 * Copyright:   Copyright (c) Microsoft Corporation
 *
 * Contents:    This SDK is not supported under any Microsoft standard support 
 *              program or service. The information is provided AS IS without 
 *              warranty of any kind. Microsoft disclaims all implied 
 *              warranties including, without limitation, any implied 
 *              warranties of merchantability or of fitness for a particular 
 *              purpose. The entire risk arising out of the use of this SDK 
 *              remains with you. In no event shall Microsoft, its authors, or 
 *              anyone else involved in the creation, production, or delivery 
 *              of this SDK be liable for any damages whatsoever (including, 
 *              without limitation, damages for loss of business profits, 
 *              business interruption, loss of business information, or other 
 *              pecuniary loss) arising out of the use of or inability to use 
 *              this SDK, even if Microsoft has been advised of the possibility 
 *              of such damages.
 *
 *-----------------------------------------------------------------------------
 */

#if !defined(SQLODBC_VER)
#define SQLODBC_VER 1700
#endif

#if SQLODBC_VER >= 1700

#define SQLODBC_PRODUCT_NAME_FULL_VER_ANSI      "Microsoft ODBC Driver 17 for SQL Server"
#define SQLODBC_PRODUCT_NAME_FULL_ANSI          "Microsoft ODBC Driver for SQL Server"
#define SQLODBC_PRODUCT_NAME_SHORT_VER_ANSI     "ODBC Driver 17 for SQL Server"
#define SQLODBC_PRODUCT_NAME_SHORT_ANSI         "ODBC Driver for SQL Server"

#endif /* SQLODBC_VER >= 1700 */

#define SQLODBC_PRODUCT_NAME_FULL_VER           SQLODBC_PRODUCT_NAME_FULL_VER_ANSI
#define SQLODBC_PRODUCT_NAME_FULL               SQLODBC_PRODUCT_NAME_FULL_ANSI
#define SQLODBC_PRODUCT_NAME_SHORT_VER          SQLODBC_PRODUCT_NAME_SHORT_VER_ANSI
#define SQLODBC_PRODUCT_NAME_SHORT              SQLODBC_PRODUCT_NAME_SHORT_ANSI

#define SQLODBC_DRIVER_NAME                     SQLODBC_PRODUCT_NAME_SHORT_VER


#ifdef ODBCVER

#ifdef __cplusplus
extern "C" {
#endif

/* max SQL Server identifier length */
#define SQL_MAX_SQLSERVERNAME                       128

/*
 * SQLSetConnectAttr driver specific defines.
 * Microsoft has 1200 thru 1249 reserved for Microsoft ODBC Driver for SQL Server usage.
 * Connection attributes
 */
#define SQL_COPT_SS_BASE                                1200
#define SQL_COPT_SS_REMOTE_PWD                          (SQL_COPT_SS_BASE+1)  /* dbrpwset SQLSetConnectOption only */
#define SQL_COPT_SS_USE_PROC_FOR_PREP                   (SQL_COPT_SS_BASE+2)  /* Use create proc for SQLPrepare */
#define SQL_COPT_SS_INTEGRATED_SECURITY                 (SQL_COPT_SS_BASE+3)  /* Force integrated security on login */
#define SQL_COPT_SS_PRESERVE_CURSORS                    (SQL_COPT_SS_BASE+4)  /* Preserve server cursors after SQLTransact */
#define SQL_COPT_SS_USER_DATA                           (SQL_COPT_SS_BASE+5)  /* dbgetuserdata/dbsetuserdata */
#define SQL_COPT_SS_FALLBACK_CONNECT                    (SQL_COPT_SS_BASE+10) /* Enables FallBack connections */
#define SQL_COPT_SS_QUOTED_IDENT                        (SQL_COPT_SS_BASE+17) /* Enable/Disable Quoted Identifiers */
#define SQL_COPT_SS_ANSI_NPW                            (SQL_COPT_SS_BASE+18) /* Enable/Disable ANSI NULL, Padding and Warnings */
#define SQL_COPT_SS_BCP                                 (SQL_COPT_SS_BASE+19) /* Allow BCP usage on connection */
#define SQL_COPT_SS_TRANSLATE                           (SQL_COPT_SS_BASE+20) /* Perform code page translation */
#define SQL_COPT_SS_ATTACHDBFILENAME                    (SQL_COPT_SS_BASE+21) /* File name to be attached as a database */
#define SQL_COPT_SS_CONCAT_NULL                         (SQL_COPT_SS_BASE+22) /* Enable/Disable CONCAT_NULL_YIELDS_NULL */
#define SQL_COPT_SS_ENCRYPT                             (SQL_COPT_SS_BASE+23) /* Allow strong encryption for data */
#define SQL_COPT_SS_MARS_ENABLED                        (SQL_COPT_SS_BASE+24) /* Multiple active result set per connection */
#define SQL_COPT_SS_OLDPWD                              (SQL_COPT_SS_BASE+26) /* Old Password, used when changing password during login */
#define SQL_COPT_SS_TXN_ISOLATION                       (SQL_COPT_SS_BASE+27) /* Used to set/get any driver-specific or ODBC-defined TXN iso level */
#define SQL_COPT_SS_TRUST_SERVER_CERTIFICATE            (SQL_COPT_SS_BASE+28) /* Trust server certificate */
#define SQL_COPT_SS_SERVER_SPN                          (SQL_COPT_SS_BASE+29) /* Server SPN */
#define SQL_COPT_SS_INTEGRATED_AUTHENTICATION_METHOD    (SQL_COPT_SS_BASE+31) /* The integrated authentication method used for the connection */
#define SQL_COPT_SS_MUTUALLY_AUTHENTICATED              (SQL_COPT_SS_BASE+32) /* Used to decide if the connection is mutually authenticated */
#define SQL_COPT_SS_CLIENT_CONNECTION_ID                (SQL_COPT_SS_BASE+33) /* Post connection attribute used to get the ConnectionIDMET */
/*
 * SQLSetStmtAttr Microsoft ODBC Driver for SQL Server specific defines.
 * Statement attributes
 */
#define SQL_SOPT_SS_BASE                            1225
#define SQL_SOPT_SS_TEXTPTR_LOGGING                 (SQL_SOPT_SS_BASE+0) /* Text pointer logging */
#define SQL_SOPT_SS_CURRENT_COMMAND                 (SQL_SOPT_SS_BASE+1) /* dbcurcmd SQLGetStmtOption only */
#define SQL_SOPT_SS_HIDDEN_COLUMNS                  (SQL_SOPT_SS_BASE+2) /* Expose FOR BROWSE hidden columns */
#define SQL_SOPT_SS_NOBROWSETABLE                   (SQL_SOPT_SS_BASE+3) /* Set NOBROWSETABLE option */
#define SQL_SOPT_SS_CURSOR_OPTIONS                  (SQL_SOPT_SS_BASE+5) /* Server cursor options */
#define SQL_SOPT_SS_NOCOUNT_STATUS                  (SQL_SOPT_SS_BASE+6) /* Real vs. Not Real row count indicator */
#define SQL_SOPT_SS_DEFER_PREPARE                   (SQL_SOPT_SS_BASE+7) /* Defer prepare until necessary */
#define SQL_SOPT_SS_QUERYNOTIFICATION_TIMEOUT       (SQL_SOPT_SS_BASE+8) /* Notification timeout */
#define SQL_SOPT_SS_QUERYNOTIFICATION_MSGTEXT       (SQL_SOPT_SS_BASE+9) /* Notification message text */
#define SQL_SOPT_SS_QUERYNOTIFICATION_OPTIONS       (SQL_SOPT_SS_BASE+10)/* SQL service broker name */
#define SQL_SOPT_SS_PARAM_FOCUS                     (SQL_SOPT_SS_BASE+11)/* Direct subsequent calls to parameter related methods to set properties on constituent columns/parameters of container types */
#define SQL_SOPT_SS_NAME_SCOPE                      (SQL_SOPT_SS_BASE+12)/* Sets name scope for subsequent catalog function calls */
#define SQL_SOPT_SS_COLUMN_ENCRYPTION               (SQL_SOPT_SS_BASE+13)/* Sets the column encryption mode */
#define SQL_SOPT_SS_MAX_USED                        SQL_SOPT_SS_COLUMN_ENCRYPTION
 /* Define old names */
#define SQL_TEXTPTR_LOGGING                         SQL_SOPT_SS_TEXTPTR_LOGGING
#define SQL_COPT_SS_BASE_EX                         1240
#define SQL_COPT_SS_BROWSE_CONNECT                  (SQL_COPT_SS_BASE_EX+1) /* Browse connect mode of operation */
#define SQL_COPT_SS_BROWSE_SERVER                   (SQL_COPT_SS_BASE_EX+2) /* Single Server browse request. */
#define SQL_COPT_SS_WARN_ON_CP_ERROR                (SQL_COPT_SS_BASE_EX+3) /* Issues warning when data from the server had a loss during code page conversion. */
#define SQL_COPT_SS_CONNECTION_DEAD                 (SQL_COPT_SS_BASE_EX+4) /* dbdead SQLGetConnectOption only. It will try to ping the server. Expensive connection check */
#define SQL_COPT_SS_BROWSE_CACHE_DATA               (SQL_COPT_SS_BASE_EX+5) /* Determines if we should cache browse info. Used when returned buffer is greater then ODBC limit (32K) */
#define SQL_COPT_SS_RESET_CONNECTION                (SQL_COPT_SS_BASE_EX+6) /* When this option is set, we will perform connection reset on next packet */
#define SQL_COPT_SS_APPLICATION_INTENT              (SQL_COPT_SS_BASE_EX+7) /* Application Intent */
#define SQL_COPT_SS_MULTISUBNET_FAILOVER            (SQL_COPT_SS_BASE_EX+8) /* Multi-subnet Failover */
#define SQL_COPT_SS_TNIR                            (SQL_COPT_SS_BASE_EX+9) /* Transparent Network IP Resolution */
#define SQL_COPT_SS_COLUMN_ENCRYPTION               (SQL_COPT_SS_BASE_EX+10) /* Column Encryption Enabled or Disabled */
#define SQL_COPT_SS_CEKEYSTOREPROVIDER              (SQL_COPT_SS_BASE_EX+11) /* Load a keystore provider or read the list of loaded keystore providers */
#define SQL_COPT_SS_CEKEYSTOREDATA                  (SQL_COPT_SS_BASE_EX+12) /* Communicate with loaded keystore providers */
#define SQL_COPT_SS_TRUSTEDCMKPATHS                 (SQL_COPT_SS_BASE_EX+13) /* List of trusted CMK paths */
#define SQL_COPT_SS_CEKCACHETTL                     (SQL_COPT_SS_BASE_EX+14) /* Symmetric Key Cache TTL */
#define SQL_COPT_SS_AUTHENTICATION                  (SQL_COPT_SS_BASE_EX+15) /* The authentication method used for the connection */
#define SQL_COPT_SS_ACCESS_TOKEN                    (SQL_COPT_SS_BASE_EX+16) /* The authentication access token used for the connection */
#define SQL_COPT_SS_USE_FMTONLY                     (SQL_COPT_SS_BASE_EX+17) /* The flag to SET FMTONLY ON/OFF */


/* SQLSetConnectAttr MS driver additional specific defines. */
#define SQL_COPT_SS_BASE_ADD                        1400
#define SQL_COPT_SS_DATACLASSIFICATION_VERSION      (SQL_COPT_SS_BASE_ADD + 1) /* The flag to Set/Get DATACLASSIFICATION version support */


 /*
 * SQLColAttributes driver specific defines.
 * SQLSetDescField/SQLGetDescField driver specific defines.
 * Microsoft has 1200 thru 1249 reserved for Microsoft ODBC Driver for SQL Server usage.
 */
#define SQL_CA_SS_BASE                              1200
#define SQL_CA_SS_COLUMN_SSTYPE                     (SQL_CA_SS_BASE+0)   /*  dbcoltype/dbalttype */
#define SQL_CA_SS_COLUMN_UTYPE                      (SQL_CA_SS_BASE+1)   /*  dbcolutype/dbaltutype */
#define SQL_CA_SS_NUM_ORDERS                        (SQL_CA_SS_BASE+2)   /*  dbnumorders */
#define SQL_CA_SS_COLUMN_ORDER                      (SQL_CA_SS_BASE+3)   /*  dbordercol */
#define SQL_CA_SS_COLUMN_VARYLEN                    (SQL_CA_SS_BASE+4)   /*  dbvarylen */
#define SQL_CA_SS_NUM_COMPUTES                      (SQL_CA_SS_BASE+5)   /*  dbnumcompute */
#define SQL_CA_SS_COMPUTE_ID                        (SQL_CA_SS_BASE+6)   /*  dbnextrow status return */
#define SQL_CA_SS_COMPUTE_BYLIST                    (SQL_CA_SS_BASE+7)   /*  dbbylist */
#define SQL_CA_SS_COLUMN_ID                         (SQL_CA_SS_BASE+8)   /*  dbaltcolid */
#define SQL_CA_SS_COLUMN_OP                         (SQL_CA_SS_BASE+9)   /*  dbaltop */
#define SQL_CA_SS_COLUMN_SIZE                       (SQL_CA_SS_BASE+10)  /*  dbcollen */
#define SQL_CA_SS_COLUMN_HIDDEN                     (SQL_CA_SS_BASE+11)  /*  Column is hidden (FOR BROWSE) */
#define SQL_CA_SS_COLUMN_KEY                        (SQL_CA_SS_BASE+12)  /*  Column is key column (FOR BROWSE) */
#define SQL_CA_SS_COLUMN_COLLATION                  (SQL_CA_SS_BASE+14)  /*  Column collation (only for chars) */
#define SQL_CA_SS_VARIANT_TYPE                      (SQL_CA_SS_BASE+15)
#define SQL_CA_SS_VARIANT_SQL_TYPE                  (SQL_CA_SS_BASE+16)
#define SQL_CA_SS_VARIANT_SERVER_TYPE               (SQL_CA_SS_BASE+17)

/* XML, CLR UDT, and table valued parameter related metadata */
#define SQL_CA_SS_UDT_CATALOG_NAME                  (SQL_CA_SS_BASE+18) /*  UDT catalog name */
#define SQL_CA_SS_UDT_SCHEMA_NAME                   (SQL_CA_SS_BASE+19) /*  UDT schema name */
#define SQL_CA_SS_UDT_TYPE_NAME                     (SQL_CA_SS_BASE+20) /*  UDT type name */
#define SQL_CA_SS_UDT_ASSEMBLY_TYPE_NAME            (SQL_CA_SS_BASE+21) /*  Qualified name of the assembly containing the UDT class */
#define SQL_CA_SS_XML_SCHEMACOLLECTION_CATALOG_NAME (SQL_CA_SS_BASE+22) /*  Name of the catalog that contains XML Schema collection */
#define SQL_CA_SS_XML_SCHEMACOLLECTION_SCHEMA_NAME  (SQL_CA_SS_BASE+23) /*  Name of the schema that contains XML Schema collection */
#define SQL_CA_SS_XML_SCHEMACOLLECTION_NAME         (SQL_CA_SS_BASE+24) /*  Name of the XML Schema collection */
#define SQL_CA_SS_CATALOG_NAME                      (SQL_CA_SS_BASE+25) /*  Catalog name */
#define SQL_CA_SS_SCHEMA_NAME                       (SQL_CA_SS_BASE+26) /*  Schema name */
#define SQL_CA_SS_TYPE_NAME                         (SQL_CA_SS_BASE+27) /*  Type name */

/* table valued parameter related metadata */
#define SQL_CA_SS_COLUMN_COMPUTED                   (SQL_CA_SS_BASE+29) /*  column is computed */
#define SQL_CA_SS_COLUMN_IN_UNIQUE_KEY              (SQL_CA_SS_BASE+30) /*  column is part of a unique key */
#define SQL_CA_SS_COLUMN_SORT_ORDER                 (SQL_CA_SS_BASE+31) /*  column sort order */
#define SQL_CA_SS_COLUMN_SORT_ORDINAL               (SQL_CA_SS_BASE+32) /*  column sort ordinal */
#define SQL_CA_SS_COLUMN_HAS_DEFAULT_VALUE          (SQL_CA_SS_BASE+33) /*  column has default value for all rows of the table valued parameter */

/* sparse column related metadata */
#define SQL_CA_SS_IS_COLUMN_SET                     (SQL_CA_SS_BASE+34) /*  column is a column-set column for sparse columns */

/* Legacy datetime related metadata */
#define SQL_CA_SS_SERVER_TYPE                       (SQL_CA_SS_BASE+35) /*  column type to send on the wire for datetime types */

/* force column encryption */
#define SQL_CA_SS_FORCE_ENCRYPT                     (SQL_CA_SS_BASE+36) /*  indicate mandatory encryption for this parameter */

/* Data Classification */
#define SQL_CA_SS_DATA_CLASSIFICATION               (SQL_CA_SS_BASE+37) /*  retrieve data classification information */

/* Data Classification version*/
#define SQL_CA_SS_DATA_CLASSIFICATION_VERSION       (SQL_CA_SS_BASE+38) /*  retrieve data classification version */

/* Defines for use with SQL_COPT_SS_PRESERVE_CURSORS */
#define SQL_PC_OFF                          0L           /*  Cursors are closed on SQLTransact */
#define SQL_PC_ON                           1L           /*  Cursors remain open on SQLTransact */
#define SQL_PC_DEFAULT                      SQL_PC_OFF
/* Defines for use with SQL_COPT_SS_USE_PROC_FOR_PREP */
#define SQL_UP_OFF                          0L           /*  Procedures won't be used for prepare */
#define SQL_UP_ON                           1L           /*  Procedures will be used for prepare */
#define SQL_UP_ON_DROP                      2L           /*  Temp procedures will be explicitly dropped */
#define SQL_UP_DEFAULT                      SQL_UP_ON
/* Defines for use with SQL_COPT_SS_INTEGRATED_SECURITY - Pre-Connect Option only */
#define SQL_IS_OFF                          0L
#define SQL_IS_ON                           1L
#define SQL_IS_DEFAULT                      SQL_IS_OFF
/* Defines for use with SQL_COPT_SS_AUTHENTICATION - Pre-Connect Option only */
#define SQL_AU_NONE                         0L           /*  Authentication not used */
#define SQL_AU_PASSWORD                     1L           /*  SQL server authentication is used */
#define SQL_AU_AD_INTEGRATED                2L           /*  Active Directory integrated authentication is used */
#define SQL_AU_AD_PASSWORD                  3L           /*  Active Directory password authentication is used */
#define SQL_AU_RESET                        5L           /*  Reset the value to attribute not set to anything. */
#define SQL_AU_AD_MSI                       6L           /*  Active Directory Manage Service Identity authentication is used */

/* Defines for use with SQL_COPT_SS_TRANSLATE */
#define SQL_XL_OFF                          0L           /*  Code page translation is not performed */
#define SQL_XL_ON                           1L           /*  Code page translation is performed */
#define SQL_XL_DEFAULT                      SQL_XL_ON
/* Defines for use with SQL_COPT_SS_BCP - Pre-Connect Option only */
#define SQL_BCP_OFF                         0L           /*  BCP is not allowed on connection */
#define SQL_BCP_ON                          1L           /*  BCP is allowed on connection */
#define SQL_BCP_DEFAULT                     SQL_BCP_OFF
/* Defines for use with SQL_COPT_SS_QUOTED_IDENT */
#define SQL_QI_OFF                          0L           /*  Quoted identifiers are enable */
#define SQL_QI_ON                           1L           /*  Quoted identifiers are disabled */
#define SQL_QI_DEFAULT                      SQL_QI_ON
/* Defines for use with SQL_COPT_SS_ANSI_NPW - Pre-Connect Option only */
#define SQL_AD_OFF                          0L           /*  ANSI NULLs, Padding and Warnings are enabled */
#define SQL_AD_ON                           1L           /*  ANSI NULLs, Padding and Warnings are disabled */
#define SQL_AD_DEFAULT                      SQL_AD_ON
/* Defines for use with SQL_COPT_SS_CONCAT_NULL - Pre-Connect Option only */
#define SQL_CN_OFF                          0L           /*  CONCAT_NULL_YIELDS_NULL is off */
#define SQL_CN_ON                           1L           /*  CONCAT_NULL_YIELDS_NULL is on */
#define SQL_CN_DEFAULT                      SQL_CN_ON
/* Defines for use with SQL_SOPT_SS_TEXTPTR_LOGGING */
#define SQL_TL_OFF                          0L           /*  No logging on text pointer ops */
#define SQL_TL_ON                           1L           /*  Logging occurs on text pointer ops */
#define SQL_TL_DEFAULT                      SQL_TL_ON
/* Defines for use with SQL_SOPT_SS_HIDDEN_COLUMNS */
#define SQL_HC_OFF                          0L           /*  FOR BROWSE columns are hidden */
#define SQL_HC_ON                           1L           /*  FOR BROWSE columns are exposed */
#define SQL_HC_DEFAULT                      SQL_HC_OFF
/* Defines for use with SQL_SOPT_SS_NOBROWSETABLE */
#define SQL_NB_OFF                          0L           /*  NO_BROWSETABLE is off */
#define SQL_NB_ON                           1L           /*  NO_BROWSETABLE is on */
#define SQL_NB_DEFAULT                      SQL_NB_OFF
/* Defines for use with SQL_SOPT_SS_CURSOR_OPTIONS */
#define SQL_CO_OFF                          0L           /*  Clear all cursor options */
#define SQL_CO_FFO                          1L           /*  Fast-forward cursor will be used */
#define SQL_CO_AF                           2L           /*  Autofetch on cursor open */
#define SQL_CO_FFO_AF                       (SQL_CO_FFO|SQL_CO_AF)  /*  Fast-forward cursor with autofetch */
#define SQL_CO_FIREHOSE_AF                  4L           /*  Auto fetch on fire-hose cursors */
#define SQL_CO_DEFAULT                      SQL_CO_OFF
/* Defines for use with SQL_SOPT_SS_COLUMN_ENCRYPTION */
#define SQL_CE_DISABLED                     0L           /*  Disabled */
#define SQL_CE_RESULTSETONLY                1L           /*  Decryption Only (resultsets and return values) */
#define SQL_CE_ENABLED                      3L           /*  Enabled (both encryption and decryption) */
/* SQL_SOPT_SS_NOCOUNT_STATUS */
#define SQL_NC_OFF                          0L
#define SQL_NC_ON                           1L
#define SQL_NC_ON                           1L
/* SQL_SOPT_SS_DEFER_PREPARE */
#define SQL_DP_OFF                          0L
#define SQL_DP_ON                           1L
/* SQL_SOPT_SS_NAME_SCOPE */
#define SQL_SS_NAME_SCOPE_TABLE             0L
#define SQL_SS_NAME_SCOPE_TABLE_TYPE        1L
#define SQL_SS_NAME_SCOPE_EXTENDED          2L
#define SQL_SS_NAME_SCOPE_SPARSE_COLUMN_SET 3L
#define SQL_SS_NAME_SCOPE_DEFAULT           SQL_SS_NAME_SCOPE_TABLE
/* SQL_COPT_SS_ENCRYPT */
#define SQL_EN_OFF                          0L
#define SQL_EN_ON                           1L
/* SQL_COPT_SS_TRUST_SERVER_CERTIFICATE */
#define SQL_TRUST_SERVER_CERTIFICATE_NO     0L
#define SQL_TRUST_SERVER_CERTIFICATE_YES    1L
/* SQL_COPT_SS_BROWSE_CONNECT */
#define SQL_MORE_INFO_NO                    0L
#define SQL_MORE_INFO_YES                   1L
/* SQL_COPT_SS_BROWSE_CACHE_DATA */
#define SQL_CACHE_DATA_NO                   0L
#define SQL_CACHE_DATA_YES                  1L
/* SQL_COPT_SS_RESET_CONNECTION */
#define SQL_RESET_YES                       1L
/* SQL_COPT_SS_WARN_ON_CP_ERROR */
#define SQL_WARN_NO                         0L
#define SQL_WARN_YES                        1L
/* SQL_COPT_SS_MARS_ENABLED */
#define SQL_MARS_ENABLED_NO                 0L
#define SQL_MARS_ENABLED_YES                1L
/* SQL_TXN_ISOLATION_OPTION bitmasks */
#define SQL_TXN_SS_SNAPSHOT                 0x00000020L
/* SQL_COPT_SS_COLUMN_ENCRYPTION */
#define SQL_COLUMN_ENCRYPTION_DISABLE       0L
#define SQL_COLUMN_ENCRYPTION_ENABLE        1L
#define SQL_COLUMN_ENCRYPTION_DEFAULT       SQL_COLUMN_ENCRYPTION_DISABLE
/* SQL_COPT_SS_CEKCACHETTL */
#define SQL_CEKCACHETTL_DEFAULT             7200L        /*  TTL value in seconds (2 hours) */

/* The following are defines for SQL_CA_SS_COLUMN_SORT_ORDER */
#define SQL_SS_ORDER_UNSPECIFIED            0L
#define SQL_SS_DESCENDING_ORDER             1L
#define SQL_SS_ASCENDING_ORDER              2L
#define SQL_SS_ORDER_DEFAULT                SQL_SS_ORDER_UNSPECIFIED

/*
 * Driver specific SQL data type defines.
 * Microsoft has -150 thru -199 reserved for Microsoft ODBC Driver for SQL Server usage.
 */
#define SQL_SS_VARIANT                      (-150)
#define SQL_SS_UDT                          (-151)
#define SQL_SS_XML                          (-152)
#define SQL_SS_TABLE                        (-153)
#define SQL_SS_TIME2                        (-154)
#define SQL_SS_TIMESTAMPOFFSET              (-155)

/* Local types to be used with SQL_CA_SS_SERVER_TYPE */
#define SQL_SS_TYPE_DEFAULT                         0L
#define SQL_SS_TYPE_SMALLDATETIME                   1L
#define SQL_SS_TYPE_DATETIME                        2L

/* Extended C Types range 4000 and above. Range of -100 thru 200 is reserved by Driver Manager. */
#define SQL_C_TYPES_EXTENDED                0x04000L

/*
 * SQL_SS_LENGTH_UNLIMITED is used to describe the max length of
 * VARCHAR(max), VARBINARY(max), NVARCHAR(max), and XML columns
 */
#define SQL_SS_LENGTH_UNLIMITED             0

/*
 * User Data Type definitions.
 * Returned by SQLColAttributes/SQL_CA_SS_COLUMN_UTYPE.
 */
#define SQLudtBINARY                        3
#define SQLudtBIT                           16
#define SQLudtBITN                          0
#define SQLudtCHAR                          1
#define SQLudtDATETIM4                      22
#define SQLudtDATETIME                      12
#define SQLudtDATETIMN                      15
#define SQLudtDECML                         24
#define SQLudtDECMLN                        26
#define SQLudtFLT4                          23
#define SQLudtFLT8                          8
#define SQLudtFLTN                          14
#define SQLudtIMAGE                         20
#define SQLudtINT1                          5
#define SQLudtINT2                          6
#define SQLudtINT4                          7
#define SQLudtINTN                          13
#define SQLudtMONEY                         11
#define SQLudtMONEY4                        21
#define SQLudtMONEYN                        17
#define SQLudtNUM                           10
#define SQLudtNUMN                          25
#define SQLudtSYSNAME                       18
#define SQLudtTEXT                          19
#define SQLudtTIMESTAMP                     80
#define SQLudtUNIQUEIDENTIFIER              0
#define SQLudtVARBINARY                     4
#define SQLudtVARCHAR                       2
#define MIN_USER_DATATYPE                   256
/*
 * Aggregate operator types.
 * Returned by SQLColAttributes/SQL_CA_SS_COLUMN_OP.
 */
#define SQLAOPSTDEV                         0x30    /* Standard deviation */
#define SQLAOPSTDEVP                        0x31    /* Standard deviation population */
#define SQLAOPVAR                           0x32    /* Variance */
#define SQLAOPVARP                          0x33    /* Variance population */
#define SQLAOPCNT                           0x4b    /* Count */
#define SQLAOPSUM                           0x4d    /* Sum */
#define SQLAOPAVG                           0x4f    /* Average */
#define SQLAOPMIN                           0x51    /* Min */
#define SQLAOPMAX                           0x52    /* Max */
#define SQLAOPANY                           0x53    /* Any */
#define SQLAOPNOOP                          0x56    /* None */
/*
 * SQLGetDiagField driver specific defines.
 * Microsoft has -1150 thru -1199 reserved for Microsoft ODBC Driver for SQL Server usage.
 */
#define SQL_DIAG_SS_BASE                    (-1150)
#define SQL_DIAG_SS_MSGSTATE                (SQL_DIAG_SS_BASE)
#define SQL_DIAG_SS_SEVERITY                (SQL_DIAG_SS_BASE-1)
#define SQL_DIAG_SS_SRVNAME                 (SQL_DIAG_SS_BASE-2)
#define SQL_DIAG_SS_PROCNAME                (SQL_DIAG_SS_BASE-3)
#define SQL_DIAG_SS_LINE                    (SQL_DIAG_SS_BASE-4)
/*
 * SQLGetDiagField/SQL_DIAG_DYNAMIC_FUNCTION_CODE driver specific defines.
 * Microsoft has -200 thru -299 reserved for Microsoft ODBC Driver for SQL Server usage.
 */
#define SQL_DIAG_DFC_SS_BASE                (-200)
#define SQL_DIAG_DFC_SS_ALTER_DATABASE      (SQL_DIAG_DFC_SS_BASE-0)
#define SQL_DIAG_DFC_SS_CHECKPOINT          (SQL_DIAG_DFC_SS_BASE-1)
#define SQL_DIAG_DFC_SS_CONDITION           (SQL_DIAG_DFC_SS_BASE-2)
#define SQL_DIAG_DFC_SS_CREATE_DATABASE     (SQL_DIAG_DFC_SS_BASE-3)
#define SQL_DIAG_DFC_SS_CREATE_DEFAULT      (SQL_DIAG_DFC_SS_BASE-4)
#define SQL_DIAG_DFC_SS_CREATE_PROCEDURE    (SQL_DIAG_DFC_SS_BASE-5)
#define SQL_DIAG_DFC_SS_CREATE_RULE         (SQL_DIAG_DFC_SS_BASE-6)
#define SQL_DIAG_DFC_SS_CREATE_TRIGGER      (SQL_DIAG_DFC_SS_BASE-7)
#define SQL_DIAG_DFC_SS_CURSOR_DECLARE      (SQL_DIAG_DFC_SS_BASE-8)
#define SQL_DIAG_DFC_SS_CURSOR_OPEN         (SQL_DIAG_DFC_SS_BASE-9)
#define SQL_DIAG_DFC_SS_CURSOR_FETCH        (SQL_DIAG_DFC_SS_BASE-10)
#define SQL_DIAG_DFC_SS_CURSOR_CLOSE        (SQL_DIAG_DFC_SS_BASE-11)
#define SQL_DIAG_DFC_SS_DEALLOCATE_CURSOR   (SQL_DIAG_DFC_SS_BASE-12)
#define SQL_DIAG_DFC_SS_DBCC                (SQL_DIAG_DFC_SS_BASE-13)
#define SQL_DIAG_DFC_SS_DISK                (SQL_DIAG_DFC_SS_BASE-14)
#define SQL_DIAG_DFC_SS_DROP_DATABASE       (SQL_DIAG_DFC_SS_BASE-15)
#define SQL_DIAG_DFC_SS_DROP_DEFAULT        (SQL_DIAG_DFC_SS_BASE-16)
#define SQL_DIAG_DFC_SS_DROP_PROCEDURE      (SQL_DIAG_DFC_SS_BASE-17)
#define SQL_DIAG_DFC_SS_DROP_RULE           (SQL_DIAG_DFC_SS_BASE-18)
#define SQL_DIAG_DFC_SS_DROP_TRIGGER        (SQL_DIAG_DFC_SS_BASE-19)
#define SQL_DIAG_DFC_SS_DUMP_DATABASE       (SQL_DIAG_DFC_SS_BASE-20)
#define SQL_DIAG_DFC_SS_BACKUP_DATABASE     (SQL_DIAG_DFC_SS_BASE-20)
#define SQL_DIAG_DFC_SS_DUMP_TABLE          (SQL_DIAG_DFC_SS_BASE-21)
#define SQL_DIAG_DFC_SS_DUMP_TRANSACTION    (SQL_DIAG_DFC_SS_BASE-22)
#define SQL_DIAG_DFC_SS_BACKUP_TRANSACTION  (SQL_DIAG_DFC_SS_BASE-22)
#define SQL_DIAG_DFC_SS_GOTO                (SQL_DIAG_DFC_SS_BASE-23)
#define SQL_DIAG_DFC_SS_INSERT_BULK         (SQL_DIAG_DFC_SS_BASE-24)
#define SQL_DIAG_DFC_SS_KILL                (SQL_DIAG_DFC_SS_BASE-25)
#define SQL_DIAG_DFC_SS_LOAD_DATABASE       (SQL_DIAG_DFC_SS_BASE-26)
#define SQL_DIAG_DFC_SS_RESTORE_DATABASE    (SQL_DIAG_DFC_SS_BASE-26)
#define SQL_DIAG_DFC_SS_LOAD_HEADERONLY     (SQL_DIAG_DFC_SS_BASE-27)
#define SQL_DIAG_DFC_SS_RESTORE_HEADERONLY  (SQL_DIAG_DFC_SS_BASE-27)
#define SQL_DIAG_DFC_SS_LOAD_TABLE          (SQL_DIAG_DFC_SS_BASE-28)
#define SQL_DIAG_DFC_SS_LOAD_TRANSACTION    (SQL_DIAG_DFC_SS_BASE-29)
#define SQL_DIAG_DFC_SS_RESTORE_TRANSACTION (SQL_DIAG_DFC_SS_BASE-29)
#define SQL_DIAG_DFC_SS_PRINT               (SQL_DIAG_DFC_SS_BASE-30)
#define SQL_DIAG_DFC_SS_RAISERROR           (SQL_DIAG_DFC_SS_BASE-31)
#define SQL_DIAG_DFC_SS_READTEXT            (SQL_DIAG_DFC_SS_BASE-32)
#define SQL_DIAG_DFC_SS_RECONFIGURE         (SQL_DIAG_DFC_SS_BASE-33)
#define SQL_DIAG_DFC_SS_RETURN              (SQL_DIAG_DFC_SS_BASE-34)
#define SQL_DIAG_DFC_SS_SELECT_INTO         (SQL_DIAG_DFC_SS_BASE-35)
#define SQL_DIAG_DFC_SS_SET                 (SQL_DIAG_DFC_SS_BASE-36)
#define SQL_DIAG_DFC_SS_SET_IDENTITY_INSERT (SQL_DIAG_DFC_SS_BASE-37)
#define SQL_DIAG_DFC_SS_SET_ROW_COUNT       (SQL_DIAG_DFC_SS_BASE-38)
#define SQL_DIAG_DFC_SS_SET_STATISTICS      (SQL_DIAG_DFC_SS_BASE-39)
#define SQL_DIAG_DFC_SS_SET_TEXTSIZE        (SQL_DIAG_DFC_SS_BASE-40)
#define SQL_DIAG_DFC_SS_SETUSER             (SQL_DIAG_DFC_SS_BASE-41)
#define SQL_DIAG_DFC_SS_SHUTDOWN            (SQL_DIAG_DFC_SS_BASE-42)
#define SQL_DIAG_DFC_SS_TRANS_BEGIN         (SQL_DIAG_DFC_SS_BASE-43)
#define SQL_DIAG_DFC_SS_TRANS_COMMIT        (SQL_DIAG_DFC_SS_BASE-44)
#define SQL_DIAG_DFC_SS_TRANS_PREPARE       (SQL_DIAG_DFC_SS_BASE-45)
#define SQL_DIAG_DFC_SS_TRANS_ROLLBACK      (SQL_DIAG_DFC_SS_BASE-46)
#define SQL_DIAG_DFC_SS_TRANS_SAVE          (SQL_DIAG_DFC_SS_BASE-47)
#define SQL_DIAG_DFC_SS_TRUNCATE_TABLE      (SQL_DIAG_DFC_SS_BASE-48)
#define SQL_DIAG_DFC_SS_UPDATE_STATISTICS   (SQL_DIAG_DFC_SS_BASE-49)
#define SQL_DIAG_DFC_SS_UPDATETEXT          (SQL_DIAG_DFC_SS_BASE-50)
#define SQL_DIAG_DFC_SS_USE                 (SQL_DIAG_DFC_SS_BASE-51)
#define SQL_DIAG_DFC_SS_WAITFOR             (SQL_DIAG_DFC_SS_BASE-52)
#define SQL_DIAG_DFC_SS_WRITETEXT           (SQL_DIAG_DFC_SS_BASE-53)
#define SQL_DIAG_DFC_SS_DENY                (SQL_DIAG_DFC_SS_BASE-54)
#define SQL_DIAG_DFC_SS_SET_XCTLVL          (SQL_DIAG_DFC_SS_BASE-55)
#define SQL_DIAG_DFC_SS_MERGE               (SQL_DIAG_DFC_SS_BASE-56)

/* Severity codes for SQL_DIAG_SS_SEVERITY */
#define EX_ANY          0
#define EX_INFO         10
#define EX_MAXISEVERITY EX_INFO
#define EX_MISSING      11
#define EX_TYPE         12
#define EX_DEADLOCK     13
#define EX_PERMIT       14
#define EX_SYNTAX       15
#define EX_USER         16
#define EX_RESOURCE     17
#define EX_INTOK        18
#define MAXUSEVERITY    EX_INTOK
#define EX_LIMIT        19
#define EX_CMDFATAL     20
#define MINFATALERR     EX_CMDFATAL
#define EX_DBFATAL      21
#define EX_TABCORRUPT   22
#define EX_DBCORRUPT    23
#define EX_HARDWARE     24
#define EX_CONTROL      25

#pragma pack(8)


/* New Structure for TIME2 */
typedef struct tagSS_TIME2_STRUCT
{
    SQLUSMALLINT   hour;
    SQLUSMALLINT   minute;
    SQLUSMALLINT   second;
    SQLUINTEGER    fraction;
} SQL_SS_TIME2_STRUCT;

/* New Structure for TIMESTAMPOFFSET */
typedef struct tagSS_TIMESTAMPOFFSET_STRUCT
{
    SQLSMALLINT    year;
    SQLUSMALLINT   month;
    SQLUSMALLINT   day;
    SQLUSMALLINT   hour;
    SQLUSMALLINT   minute;
    SQLUSMALLINT   second;
    SQLUINTEGER    fraction;
    SQLSMALLINT    timezone_hour;
    SQLSMALLINT    timezone_minute;
} SQL_SS_TIMESTAMPOFFSET_STRUCT;

#pragma pack()

typedef struct AccessToken
{
    unsigned int dataSize;
    char data[];
} ACCESSTOKEN;

/* 
 * Keystore Provider interface definitions 
 */
typedef struct CEKeystoreContext
{
    void *envCtx;
    void *dbcCtx;
    void *stmtCtx;
} CEKEYSTORECONTEXT;

typedef void errFunc(CEKEYSTORECONTEXT *ctx, const wchar_t *msg, ...);

#define IDS_MSG(x) ((const wchar_t*)(x))

typedef struct CEKeystoreProvider
{
    wchar_t *Name;
    int (*Init)(CEKEYSTORECONTEXT *ctx, errFunc *onError);
    int (*Read)(CEKEYSTORECONTEXT *ctx, errFunc *onError, void *data, unsigned int *len);
    int (*Write)(CEKEYSTORECONTEXT *ctx, errFunc *onError, void *data, unsigned int len);
    int (*DecryptCEK)(
        CEKEYSTORECONTEXT *ctx,
        errFunc *onError,
        const wchar_t *keyPath,
        const wchar_t *alg,
        unsigned char *ecek,
        unsigned short ecekLen,
        unsigned char **cekOut,
        unsigned short *cekLen);
    int (*EncryptCEK)(
        CEKEYSTORECONTEXT *ctx,
        errFunc *onError,
        const wchar_t *keyPath,
        const wchar_t *alg,
        unsigned char *cek,
        unsigned short cekLen,
        unsigned char **ecekOut,
        unsigned short *ecekLen);
    void (*Free)();
} CEKEYSTOREPROVIDER;

typedef struct CEKeystoreProvider2
{
    wchar_t *Name;
    int (__stdcall *Init)(CEKEYSTORECONTEXT *ctx, errFunc *onError);
    int (__stdcall *Read)(CEKEYSTORECONTEXT *ctx, errFunc *onError, void *data, unsigned int *len);
    int (__stdcall *Write)(CEKEYSTORECONTEXT *ctx, errFunc *onError, void *data, unsigned int len);
    int (__stdcall *DecryptCEK)(
        CEKEYSTORECONTEXT *ctx,
        errFunc *onError,
        const wchar_t *keyPath,
        const wchar_t *alg,
        unsigned char *ecek,
        unsigned short ecekLen,
        unsigned char **cekOut,
        unsigned short *cekLen);
    int (__stdcall *EncryptCEK)(
        CEKEYSTORECONTEXT *ctx,
        errFunc *onError,
        const wchar_t *keyPath,
        const wchar_t *alg,
        unsigned char *cek,
        unsigned short cekLen,
        unsigned char **ecekOut,
        unsigned short *ecekLen);
    int (__stdcall *VerifyCMKMetadata)(
        CEKEYSTORECONTEXT *ctx,
        errFunc *onError,
        const wchar_t *keyPath,
        unsigned char *signature,
        unsigned short sigLen);
    void *reserved;
    void (__stdcall *Free)();
} CEKEYSTOREPROVIDER2;

typedef struct CEKeystoreData
{
    wchar_t *name;
    unsigned int dataSize;
    char data[];
} CEKEYSTOREDATA;

/* The following constants are for the Azure Key Vault configuration interface */
#define AKV_CONFIG_FLAGS        0
#define AKVCFG_AUTHMODE       0x0000000F
#define AKVCFG_AUTHMODE_ACCESSTOKEN   0
#define AKVCFG_AUTHMODE_CLIENTKEY     1
#define AKVCFG_AUTHMODE_PASSWORD      2
#define AKVCFG_AUTHMODE_INTEGRATED    3
#define AKVCFG_AUTHMODE_CERTIFICATE   4
#define AKVCFG_AUTHMODE_MSI           5
#define AKVCFG_NOAUTORENEW    0x00000010

#define AKV_CONFIG_PRINCIPALID  1
#define AKV_CONFIG_AUTHSECRET   2
#define AKV_CONFIG_ACCESSTOKEN  3
#define AKV_CONFIG_TOKENEXPIRY  4
#define AKV_CONFIG_MAXRETRIES   5
#define AKV_CONFIG_RETRYTIMEOUT 6
#define AKV_CONFIG_RETRYWAIT    7

#define AKV_CONFIG_RESET        255

/*
* BCP Definitions
*/

/* Error codes */
#define SUCCEED                 1
#define FAIL                    0
#define SUCCEED_ABORT           2
#define SUCCEED_ASYNC           3

/* Transfer directions */
#define DB_IN                   1   /* Transfer from client to server */
#define DB_OUT                  2   /* Transfer from server to client */

/* bcp_control option */
#define BCPMAXERRS              1   /* Sets max errors allowed */
#define BCPFIRST                2   /* Sets first row to be copied out */
#define BCPLAST                 3   /* Sets number of rows to be copied out */
#define BCPBATCH                4   /* Sets input batch size */
#define BCPKEEPNULLS            5   /* Sets to insert NULLs for empty input values */
#define BCPABORT                6   /* Sets to have bcpexec return SUCCEED_ABORT */
#define BCPODBC                 7   /* Sets ODBC canonical character output */
#define BCPKEEPIDENTITY         8   /* Sets IDENTITY_INSERT on */
#define BCPHINTSA               10  /* Sets server BCP hints (ANSI string) */
#define BCPHINTSW               11  /* Sets server BCP hints (UNICODE string) */
#define BCPFILECP               12  /* Sets clients code page for the file */
#define BCPUNICODEFILE          13  /* Sets that the file contains unicode header */
#define BCPTEXTFILE             14  /* Sets BCP mode to expect a text file and to detect Unicode or ANSI automatically */
#define BCPFILEFMT              15  /* Sets file format version */
#define BCPFMTXML               16  /* Sets the format file type to xml */
#define BCPFIRSTEX              17  /* Starting Row for BCP operation (64 bit) */
#define BCPLASTEX               18  /* Ending Row for BCP operation (64 bit) */
#define BCPROWCOUNT             19  /* Total Number of Rows Copied (64 bit) */
#define BCPDELAYREADFMT         20  /* Delay reading format file until bcp_exec */
/* BCPFILECP values
* Any valid code page that is installed on the client can be passed plus:
*/
#define BCPFILECP_RAW           (-1) /* Data in file is in Server code page (no conversion) */
/* bcp_collen definition */
#define SQL_VARLEN_DATA (-10)   /* Use default length for column */
/* BCP column format properties */
#define BCP_FMT_TYPE            0x01
#define BCP_FMT_INDICATOR_LEN   0x02
#define BCP_FMT_DATA_LEN        0x03
#define BCP_FMT_TERMINATOR      0x04
#define BCP_FMT_SERVER_COL      0x05
#define BCP_FMT_COLLATION       0x06
#define BCP_FMT_COLLATION_ID    0x07
/* bcp_setbulkmode properties */
#define BCP_OUT_CHARACTER_MODE      0x01
#define BCP_OUT_WIDE_CHARACTER_MODE 0x02
#define BCP_OUT_NATIVE_TEXT_MODE    0x03
#define BCP_OUT_NATIVE_MODE         0x04

#ifndef INT
typedef int     INT;
typedef INT     DBINT;
typedef DBINT * LPDBINT;
typedef unsigned char DBBOOL;

#ifndef _LPCBYTE_DEFINED
#define _LPCBYTE_DEFINED
typedef BYTE const* LPCBYTE;
#endif /* _LPCBYTE_DEFINED */
#endif /* INT */

/*
* BCP functions
*/
DBINT SQL_API bcp_batch(HDBC);
RETCODE SQL_API bcp_bind(HDBC, LPCBYTE, INT, DBINT, LPCBYTE, INT, INT, INT);
RETCODE SQL_API bcp_colfmt(HDBC, INT, BYTE, INT, DBINT, LPCBYTE, INT, INT);
RETCODE SQL_API bcp_collen(HDBC, DBINT, INT);
RETCODE SQL_API bcp_colptr(HDBC, LPCBYTE, INT);
RETCODE SQL_API bcp_columns(HDBC, INT);
RETCODE SQL_API bcp_control(HDBC, INT, void *);
DBINT SQL_API bcp_done(HDBC);
RETCODE SQL_API bcp_exec(HDBC, LPDBINT);
RETCODE SQL_API bcp_getcolfmt(HDBC, INT, INT, void *, INT, INT *);
RETCODE SQL_API bcp_moretext(HDBC, DBINT, LPCBYTE);
RETCODE SQL_API bcp_sendrow(HDBC);
RETCODE SQL_API bcp_setbulkmode(HDBC, INT, void*, INT cbField, void *, INT cbRow);
RETCODE SQL_API bcp_setcolfmt(HDBC, INT, INT, void *, INT);

#ifdef UNICODE
#define bcp_init        bcp_initW
#define bcp_readfmt     bcp_readfmtW
#define bcp_writefmt    bcp_writefmtW
#define bcp_gettypename bcp_gettypenameW
#define dbprtype        dbprtypeW
#define BCPHINTS        BCPHINTSW
#else
#define bcp_init        bcp_initA
#define bcp_readfmt     bcp_readfmtA
#define bcp_writefmt    bcp_writefmtA
#define bcp_gettypename bcp_gettypenameA
#define dbprtype        dbprtypeA
#define BCPHINTS        BCPHINTSA
#endif /* UNICODE */

/* Narrow and wide character names functions */
CHAR* SQL_API bcp_gettypenameA(INT, DBBOOL);
WCHAR* SQL_API bcp_gettypenameW(INT, DBBOOL);
RETCODE SQL_API bcp_initA(HDBC, LPCSTR, LPCSTR, LPCSTR, INT);
RETCODE SQL_API bcp_initW(HDBC, LPCWSTR, LPCWSTR, LPCWSTR, INT);
RETCODE SQL_API bcp_readfmtA(HDBC, LPCSTR);
RETCODE SQL_API bcp_readfmtW(HDBC, LPCWSTR);
RETCODE SQL_API bcp_writefmtA(HDBC, LPCSTR);
RETCODE SQL_API bcp_writefmtW(HDBC, LPCWSTR);
CHAR* SQL_API dbprtypeA(INT);
WCHAR* SQL_API dbprtypeW(INT);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ODBCVER */

#endif /* __msodbcsql_h__ */

