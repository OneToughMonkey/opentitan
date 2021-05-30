%module titan_crypto
%include "stdint.i"
%include "carrays.i"

%{
    #include "crypto.h"
    #include "key.h"
%}

%include "crypto.h"
%include "key.h"

%array_class(uint8_t, uint8Array)
