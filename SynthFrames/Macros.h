#pragma once
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define true 1
#define RBP_OP_INFO 0x5

#define SPOOF_X( function, module, SSN )                                            Spoof( 0, function, module, SSN, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_A( function, module, SSN, a )                                         Spoof( 0, function, module, SSN, ( PVOID ) ( a ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_B( function, module, SSN, a, b )                                      Spoof( 0, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_C( function, module, SSN, a, b, c )                                   Spoof( 0, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_D( function, module, SSN, a, b, c, d )                                Spoof( 0, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_E( function, module, SSN, a, b, c, d, e )                             Spoof( 1, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_F( function, module, SSN, a, b, c, d, e, f )                          Spoof( 2, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_G( function, module, SSN, a, b, c, d, e, f, g )                       Spoof( 3, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_H( function, module, SSN, a, b, c, d, e, f, g, h )                    Spoof( 4, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), NULL, NULL, NULL, NULL, NULL  )
#define SPOOF_I( function, module, SSN, a, b, c, d, e, f, g, h, i )                 Spoof( 5, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), NULL, NULL, NULL, NULL )
#define SPOOF_J( function, module, SSN, a, b, c, d, e, f, g, h, i, j )              Spoof( 6, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), ( PVOID ) ( j ), NULL, NULL, NULL )
#define SPOOF_K( function, module, SSN, a, b, c, d, e, f, g, h, i, j, k )           Spoof( 7, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), ( PVOID ) ( j ), ( PVOID ) ( k ), NULL, NULL )
#define SPOOF_L( function, module, SSN, a, b, c, d, e, f, g, h, i, j, k, l )        Spoof( 8, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), ( PVOID ) ( j ), ( PVOID ) ( k ), ( PVOID ) ( l ), NULL )
#define SPOOF_M( function, module, SSN, a, b, c, d, e, f, g, h, i, j, k, l, m )     Spoof( 9, function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), ( PVOID ) ( j ), ( PVOID ) ( k ), ( PVOID ) ( l ), ( PVOID ) ( m ) )
#define SETUP_ARGS( arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17, ... ) arg17
#define SPOOF_MACRO_CHOOSER( ... ) SETUP_ARGS(__VA_ARGS__, SPOOF_M, SPOOF_L, SPOOF_K, SPOOF_J, SPOOF_I, SPOOF_H, SPOOF_G, SPOOF_F, SPOOF_E, SPOOF_D, SPOOF_C, SPOOF_B, SPOOF_A, SPOOF_X)
#define SPOOF( ... ) SPOOF_MACRO_CHOOSER (__VA_ARGS__ )( __VA_ARGS__ )