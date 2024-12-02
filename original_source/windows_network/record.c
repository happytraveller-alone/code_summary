__int64 __fastcall Ipv6pHandleRouterAdvertisement(__int64 a1, _QWORD *a2, _DWORD *a3)
{
  __int64 v3; // rax
  _QWORD *v4; // r9
  IN6_ADDR *v5; // r10
  UINT v6; // r11d
  struct _NET_BUFFER *v9; // r14
  __int64 v10; // rax
  __int64 *v11; // rsi
  __int64 v12; // rdx
  __int64 v13; // rax
  unsigned __int64 v14; // rcx
  __int64 v15; // rax
  UCHAR v16; // r8
  const IN6_ADDR *v17; // rcx
  int v18; // eax
  PVOID DataBuffer; // rax
  PMDL CurrentMdl; // rcx
  unsigned __int16 v21; // r12
  PVOID v22; // r15
  unsigned int v23; // edx
  __int16 v24; // ax
  unsigned __int8 v25; // bl
  KIRQL v26; // r13
  unsigned int DataLength; // edx
  KIRQL *v28; // rax
  unsigned __int16 v29; // r15
  ULONG v30; // r10d
  char v31; // al
  unsigned int v32; // r8d
  unsigned int v33; // ecx
  unsigned int CurrentMdlOffset; // eax
  unsigned int v35; // eax
  _QWORD *v36; // rdi
  __int64 v37; // rax
  _DWORD *v38; // rax
  __int64 v39; // rdi
  size_t v40; // r13
  unsigned int v41; // eax
  unsigned int v42; // r15d
  PRTL_DYNAMIC_HASH_TABLE_ENTRY NextEntryHashTable; // rax
  __int64 v44; // r9
  __int64 v45; // rcx
  __int64 v46; // rbx
  struct _LIST_ENTRY **p_Blink; // r15
  __int64 v48; // rdi
  __int64 v49; // r9
  __int64 *v50; // rcx
  unsigned int v51; // edx
  char v52; // r8
  bool v53; // di
  char v54; // r15
  char v55; // r12
  char v56; // r13
  __int64 v57; // rax
  int v58; // r15d
  __int64 v59; // rcx
  char v60; // al
  unsigned int v61; // r8d
  unsigned __int32 v62; // r8d
  unsigned __int64 v63; // rcx
  unsigned int v64; // r13d
  unsigned int v65; // ebx
  __int64 v66; // r12
  __int64 v67; // r15
  __int64 v68; // rbx
  PNET_BUFFER v69; // r14
  int v70; // edx
  _DWORD *v71; // rcx
  __int64 v72; // rbx
  unsigned __int16 v73; // r15
  unsigned int v74; // ecx
  bool v75; // cf
  _BYTE *v76; // rax
  unsigned __int16 v77; // bx
  ULONG v78; // edi
  ULONG v79; // ecx
  PVOID v80; // r15
  unsigned __int8 v81; // r12
  unsigned __int32 v82; // edx
  unsigned __int8 v83; // r9
  unsigned int v84; // ebx
  unsigned __int32 v85; // ecx
  unsigned int v86; // edx
  int *v87; // rcx
  unsigned int v88; // eax
  __int64 v89; // r8
  unsigned int v90; // eax
  int v91; // r9d
  char v92; // dl
  char v93; // dl
  bool v94; // zf
  char v95; // cl
  int v96; // edi
  int v97; // eax
  __int64 v98; // rbx
  int v99; // edx
  _DWORD *v100; // rcx
  __int64 v101; // rbx
  char v102; // al
  unsigned __int8 v103; // r12
  __int64 v104; // r13
  unsigned int v105; // edx
  __int64 v106; // rcx
  __int64 v107; // r8
  PKSPIN_LOCK v108; // r15
  char *v109; // r8
  unsigned int v110; // r9d
  char *v111; // rbx
  unsigned __int64 v112; // rdi
  char v113; // r14
  char v114; // r15
  unsigned int v115; // ecx
  unsigned int v116; // eax
  int v117; // ecx
  unsigned int v118; // eax
  unsigned int v119; // edx
  unsigned int v120; // eax
  __int64 v121; // rdx
  int v122; // ecx
  volatile signed __int32 *v123; // r12
  __int64 v124; // r13
  unsigned int v125; // r13d
  unsigned int v126; // ebx
  int v127; // r8d
  unsigned int FreeRoutine; // r15d
  char v129; // r12
  PRTL_AVL_TABLE *v130; // r14
  PRTL_AVL_TABLE *v131; // rcx
  PRTL_AVL_TABLE *v132; // rax
  PKSPIN_LOCK v133; // r12
  unsigned int v134; // edx
  int *v135; // r9
  char *v136; // r8
  char v137; // cl
  char v138; // al
  __int64 v139; // rbx
  unsigned int v140; // ecx
  unsigned int v141; // r13d
  __int64 v142; // rdx
  unsigned __int64 v143; // r11
  unsigned int v144; // eax
  int v145; // edx
  int v146; // r8d
  unsigned int v147; // ecx
  unsigned int v148; // edi
  unsigned int v149; // r9d
  unsigned int v150; // eax
  unsigned int v151; // eax
  __int64 v152; // rdx
  _QWORD *v153; // rbx
  __int64 result; // rax
  int v155; // ecx
  unsigned int v156; // edx
  unsigned int v157; // r10d
  unsigned int v158; // r8d
  char v159; // r8
  __int64 v160; // rdx
  unsigned __int64 v161; // rcx
  __int64 v162; // rdx
  unsigned __int64 v163; // rcx
  unsigned int v164; // ebx
  char *v166; // rax
  __int128 v167; // xmm0
  unsigned int v168; // edi
  PRTL_AVL_TABLE *v169; // rbx
  int v170; // r9d
  __int64 v171; // rcx
  char v172; // r8
  unsigned __int8 v173; // cl
  __int64 v174; // rax
  char v175; // r10
  char v176; // al
  __int64 v177; // rax
  char v178; // r8
  _QWORD *PoolWithTag; // rax
  _QWORD *v180; // rdi
  __int64 v181; // rcx
  unsigned __int8 *v182; // rax
  unsigned int v183; // r15d
  char v184; // bl
  unsigned __int32 v185; // ecx
  unsigned int v186; // edi
  __int64 v187; // rdi
  char *v188; // rax
  char *v189; // r15
  __int64 AllocateRoutine_low; // rdi
  char *v191; // rax
  char *v192; // rbx
  _BYTE *v193; // r9
  __int64 v194; // r10
  int v195; // edi
  char v196; // r11
  unsigned int *v197; // rcx
  __int64 v198; // r12
  __int64 PotentialRouterUnderLock; // rax
  int v200; // r13d
  __int64 v201; // rcx
  __int64 v202; // rdx
  UINT AlignOffset; // [rsp+20h] [rbp-E0h]
  UINT AlignOffseta; // [rsp+20h] [rbp-E0h]
  UINT AlignOffsetb; // [rsp+20h] [rbp-E0h]
  int v206; // [rsp+40h] [rbp-C0h]
  int v207; // [rsp+50h] [rbp-B0h]
  unsigned __int8 v208; // [rsp+80h] [rbp-80h]
  unsigned __int8 v209; // [rsp+80h] [rbp-80h]
  char v210; // [rsp+80h] [rbp-80h]
  unsigned __int8 v211; // [rsp+81h] [rbp-7Fh]
  unsigned __int8 v212; // [rsp+81h] [rbp-7Fh]
  __int16 v213; // [rsp+82h] [rbp-7Eh]
  unsigned __int16 v214; // [rsp+84h] [rbp-7Ch]
  char v215; // [rsp+86h] [rbp-7Ah] BYREF
  KIRQL NewIrql; // [rsp+87h] [rbp-79h]
  __int64 v217; // [rsp+88h] [rbp-78h]
  char v218; // [rsp+90h] [rbp-70h]
  unsigned int v219; // [rsp+94h] [rbp-6Ch]
  unsigned int v220; // [rsp+98h] [rbp-68h]
  unsigned int v221; // [rsp+9Ch] [rbp-64h]
  unsigned int v222; // [rsp+A0h] [rbp-60h]
  char v223[8]; // [rsp+A8h] [rbp-58h]
  char *v224; // [rsp+B0h] [rbp-50h]
  char v225[8]; // [rsp+B8h] [rbp-48h]
  void *Buf2; // [rsp+C0h] [rbp-40h]
  PKSPIN_LOCK SpinLock; // [rsp+C8h] [rbp-38h]
  _BYTE *v228; // [rsp+D0h] [rbp-30h]
  char v229[4]; // [rsp+D8h] [rbp-28h] BYREF
  __int64 v230; // [rsp+E0h] [rbp-20h]
  __int16 v231; // [rsp+E8h] [rbp-18h] BYREF
  PNET_BUFFER NetBuffer; // [rsp+F0h] [rbp-10h]
  _QWORD *v233; // [rsp+F8h] [rbp-8h]
  PRTL_AVL_TABLE *v234; // [rsp+100h] [rbp+0h] BYREF
  __int64 v235; // [rsp+108h] [rbp+8h]
  __int64 v236; // [rsp+110h] [rbp+10h] BYREF
  __int64 v237; // [rsp+118h] [rbp+18h] BYREF
  __int64 v238; // [rsp+120h] [rbp+20h] BYREF
  char *v239; // [rsp+128h] [rbp+28h]
  PVOID v240; // [rsp+130h] [rbp+30h]
  __int64 v241; // [rsp+138h] [rbp+38h] BYREF
  __int64 v242; // [rsp+140h] [rbp+40h] BYREF
  struct _KLOCK_QUEUE_HANDLE LockHandle; // [rsp+148h] [rbp+48h] BYREF
  int v244; // [rsp+160h] [rbp+60h] BYREF
  __int64 v245; // [rsp+168h] [rbp+68h]
  __int64 v246; // [rsp+170h] [rbp+70h]
  __int64 v247[4]; // [rsp+178h] [rbp+78h] BYREF
  __int64 v248[5]; // [rsp+198h] [rbp+98h] BYREF
  __int128 v249; // [rsp+1C0h] [rbp+C0h] BYREF
  __int128 v250; // [rsp+1D0h] [rbp+D0h] BYREF
  struct _RTL_DYNAMIC_HASH_TABLE_CONTEXT Context; // [rsp+1E0h] [rbp+E0h] BYREF
  struct _KLOCK_QUEUE_HANDLE v252; // [rsp+1F8h] [rbp+F8h] BYREF
  struct _KLOCK_QUEUE_HANDLE v253; // [rsp+210h] [rbp+110h] BYREF
  struct _KLOCK_QUEUE_HANDLE v254; // [rsp+228h] [rbp+128h] BYREF
  struct _KLOCK_QUEUE_HANDLE v255; // [rsp+240h] [rbp+140h] BYREF
  struct _KLOCK_QUEUE_HANDLE v256; // [rsp+258h] [rbp+158h] BYREF
  struct _KLOCK_QUEUE_HANDLE v257; // [rsp+270h] [rbp+170h] BYREF
  struct _KLOCK_QUEUE_HANDLE v258; // [rsp+288h] [rbp+188h] BYREF
  int v259[4]; // [rsp+2A0h] [rbp+1A0h] BYREF
  __int128 v260; // [rsp+2B0h] [rbp+1B0h]
  ULONG DeleteCount[8]; // [rsp+2C0h] [rbp+1C0h] BYREF
  __int64 Storage[2]; // [rsp+2E0h] [rbp+1E0h] BYREF
  __int128 v263; // [rsp+2F0h] [rbp+1F0h] BYREF
  __m128i v264; // [rsp+300h] [rbp+200h] BYREF
  __int64 v265; // [rsp+310h] [rbp+210h]
  __int64 v266; // [rsp+318h] [rbp+218h]
  char v267[16]; // [rsp+320h] [rbp+220h] BYREF
  char v268[16]; // [rsp+330h] [rbp+230h] BYREF
  char v269[32]; // [rsp+340h] [rbp+240h] BYREF
  char v270[24]; // [rsp+360h] [rbp+260h] BYREF
  char v271[24]; // [rsp+378h] [rbp+278h] BYREF
  char v272[32]; // [rsp+390h] [rbp+290h] BYREF
  __m128i si128; // [rsp+3B0h] [rbp+2B0h]
  __m128i v274; // [rsp+3C0h] [rbp+2C0h]
  char v275[32]; // [rsp+3D0h] [rbp+2D0h] BYREF

  v3 = a2[1];
  v4 = a2;
  v5 = (IN6_ADDR *)a2[3];
  v6 = 0;
  v233 = a2;
  Buf2 = v5;
  v9 = *(struct _NET_BUFFER **)(v3 + 8);
  v10 = a2[26];
  NetBuffer = v9;
  SpinLock = 0i64;
  v220 = 0;
  v11 = *(__int64 **)(v10 + 8);
  Storage[0] = 0i64;
  Storage[1] = 0i64;
  *(_QWORD *)v225 = 0i64;
  v211 = *(_BYTE *)(v11[5] + 10);
  v215 = 0;
  v12 = (MEMORY[0xFFFFF78000000008] / 0x2710ui64 * (unsigned __int128)0x624DD2F1A9FBE77ui64) >> 64;
  v13 = v4[27];
  v14 = MEMORY[0xFFFFF78000000008] / 0x2710ui64 - v12;
  *a3 = 28;
  *(_QWORD *)v223 = v13;
  v15 = v4[34];
  v235 = (v12 + (v14 >> 1)) >> 8;
  //((PIPV6_HEADER) Args->IP)->HopLimit != 255
  if ( *(_BYTE *)(v15 + 7) != 0xFF )
  {
    result = v4[1];
    *(_DWORD *)(result + 140) = -1073741285;
    *a3 = 17;
    return result;
  }
  if ( *(_BYTE *)(a1 + 1) )
  {
    result = v4[1];
    *(_DWORD *)(result + 140) = -1073741285;
    *a3 = 18;
    return result;
  }
  v16 = v5->u.Byte[0];
  if ( v5->u.Byte[0] == 0xFF )
  {
    v18 = v5->u.Byte[1] & 0xF;
  }
  else
  {
    v17 = v5;
    if ( ((unsigned __int8)v5 & 1) != 0 )
    {
      v17 = (const IN6_ADDR *)&v264;
      v264 = *(__m128i *)v5;
      v16 = _mm_cvtsi128_si32(v264);
    }
    if ( v16 == 0xFE && (v17->u.Byte[1] & 0xC0) == 0x80 || IN6_IS_ADDR_LOOPBACK(v17) )
    {
      v18 = 2;
    }
    else if ( v172 == -2 && (*(_BYTE *)(v171 + 1) & 0xC0) == 0xC0 )
    {
      v18 = 5;
    }
    else
    {
      v18 = 14;
    }
  }
  if ( v18 != 2 )
  {
    result = v4[1];
    *(_DWORD *)(result + 140) = -1073741285;
    *a3 = 19;
    return result;
  }
  // NetBuffer
  if ( v9->DataLength < 0x10 )
  {
    result = v4[1];
    *(_DWORD *)(result + 140) = -1073741285;
    *a3 = 20;
    return result;
  }
  // Advertisement = NetioGetDataBuffer(NetBuffer, sizeof(ND_ROUTER_ADVERT_HEADER), &AdvertisementBuffer, 1, 0);
  DataBuffer = NdisGetDataBuffer(v9, 0x10u, Storage, 1u, v6);
  CurrentMdl = v9->CurrentMdl;
  // ParsedLength = sizeof(ND_ROUTER_ADVERT_HEADER);
  v21 = 16;
  v22 = DataBuffer;
  v23 = v9->CurrentMdlOffset + 16;
  v228 = DataBuffer;
  if ( v23 >= CurrentMdl->ByteCount )
  {
    NdisAdvanceNetBufferDataStart(v9, 0x10u, 0, 0i64);
  }
  else
  {
    v9->DataOffset += 16;
    v9->DataLength -= 16;
    v9->CurrentMdlOffset = v23;
  }
  v24 = *((_WORD *)v22 + 3);
  v25 = *((_BYTE *)v22 + 5);
  v26 = NewIrql;
  v219 = _byteswap_ulong(*((_DWORD *)v22 + 2));
  v208 = v25;
  v222 = (unsigned __int16)__ROR2__(v24, 8);
  while ( 1 )
  {
    DataLength = v9->DataLength;
    v231 = 0;
    if ( DataLength < 2 )
      break;
    v28 = (KIRQL *)NdisGetDataBuffer(v9, 2u, &v231, 1u, 0);
    v29 = 8 * v28[1];
    if ( v29 && (DataLength = v9->DataLength, v30 = v29, v29 <= DataLength) )
    {
      v26 = *v28;
      v31 = 1;
    }
    else
    {
      DataLength = v9->DataLength;
      v31 = 0;
      v30 = v29;
    }
    if ( !v31 )
      break;
    switch ( v26 )
    {
      case 1u:
        if ( (*(_DWORD *)(v11[5] + 36) & 0x210) == 16 )
        {
          if ( v29 != v211 + 2i64 )
          {
            *a3 = 21;
            goto LABEL_322;
          }
          v33 = v9->CurrentMdlOffset + 2;
          if ( v33 >= *(_DWORD *)(v9->Link.Region + 40) )
          {
            NdisAdvanceNetBufferDataStart(v9, 2u, 0, 0i64);
          }
          else
          {
            v9->DataOffset += 2;
            v9->DataLength = DataLength - 2;
            v9->CurrentMdlOffset = v33;
          }
          v29 -= 2;
          v21 += 2;
          SpinLock = (PKSPIN_LOCK)NdisGetDataBuffer(v9, v29, v275, 1u, 0);
        }
        break;
      case 3u:
        if ( v29 != 32 || *((_BYTE *)NdisGetDataBuffer(v9, 0x20u, v272, 1u, 0) + 2) > 0x80u )
        {
          *a3 = 23;
          goto LABEL_322;
        }
        break;
      case 5u:
        v236 = 0i64;
        if ( v29 != 8 )
        {
          *a3 = 22;
          goto LABEL_322;
        }
        v220 = _byteswap_ulong(*((_DWORD *)NdisGetDataBuffer(v9, 8u, &v236, 1u, 0) + 1));
        break;
      case 0x18u:
        if ( v29 > 0x18u
          || (v173 = *((_BYTE *)NdisGetDataBuffer(v9, v30, v270, 1u, 0) + 2), v173 > 0x80u)
          || v173 > 0x40u && v29 < 0x18u
          || v173 && v29 < 0x10u )
        {
          *a3 = 24;
          goto LABEL_322;
        }
        break;
      case 0x19u:
        if ( (*((_BYTE *)v11 + 404) & 0x40) != 0 && v29 < 0x18u )
          *a3 = 25;
        break;
      default:
        if ( v26 == 31 && (*((_BYTE *)v11 + 404) & 0x40) != 0 && v29 < 0x10u )
        {
          *a3 = 26;
LABEL_322:
          DataLength = v9->DataLength;
          goto LABEL_33;
        }
        break;
    }
    if ( *a3 != 28 )
      goto LABEL_322;
    if ( v29 )
    {
      v32 = v29 + v9->CurrentMdlOffset;
      if ( v32 >= *(_DWORD *)(v9->Link.Region + 40) )
      {
        NdisAdvanceNetBufferDataStart(v9, v29, 0, 0i64);
      }
      else
      {
        v9->DataOffset += v29;
        v9->DataLength -= v29;
        v9->CurrentMdlOffset = v32;
      }
    }
    v21 += v29;
  }
LABEL_33:
  CurrentMdlOffset = v9->CurrentMdlOffset;
  if ( CurrentMdlOffset >= v21 )
  {
    v9->DataOffset -= v21;
    v9->CurrentMdlOffset = CurrentMdlOffset - v21;
    v35 = v21 + DataLength;
    v9->DataLength = v35;
  }
  else
  {
    NdisRetreatNetBufferDataStart(v9, v21, 0, NetioAllocateMdl);
    v35 = v9->DataLength;
  }
  if ( v35 == v21 )
  {
    v36 = v233;
    if ( (BYTE5(WPP_MAIN_CB.Queue.Wcb.DmaWaitEntry.Flink) & 2) != 0 )
      IppTraceNeighborDiscovery(v11, Buf2, **(_QWORD **)(v233[26] + 16i64), 18i64);
    KeAcquireInStackQueuedSpinLock((PKSPIN_LOCK)v11 + 48, &LockHandle);
    while ( *((_DWORD *)v11 + 98) )
      ;
    if ( (v11[50] & 2) == 0 && (*((_BYTE *)v11 + 401) & 8) != 0 )
    {
      v37 = v11[5];
      *((_BYTE *)v11 + 488) = 1;
      if ( (*(_DWORD *)(v37 + 36) & 2) != 0 )
      {
        v224 = (char *)(v11 + 60);
LABEL_44:
        KeAcquireInStackQueuedSpinLockAtDpcLevel((PKSPIN_LOCK)v11 + 36, &v253);
        while ( *((_DWORD *)v11 + 74) )
          ;
        v38 = (_DWORD *)*v11;
        v39 = v11[42];
        v230 = v39;
        v40 = *(unsigned __int16 *)(*(_QWORD *)(*((_QWORD *)v38 + 5) + 16i64) + 6i64);
        v217 = 0i64;
        v41 = RtlCompute37Hash((unsigned int)g_37HashSeed, Buf2, v40);
        v42 = RtlCompute37Hash(v41, v11 + 1, 4i64) | 0x80000000;
        *(_OWORD *)&Context.ChainHead = 0i64;
        _InterlockedAdd((volatile signed __int32 *)(v39 + 8), 1u);
        if ( !KeTestSpinLock((PKSPIN_LOCK)v39) )
        {
          _InterlockedDecrement((volatile signed __int32 *)(v39 + 8));
          KeAcquireInStackQueuedSpinLockAtDpcLevel((PKSPIN_LOCK)v39, &v252);
          _InterlockedAdd((volatile signed __int32 *)(v39 + 8), 1u);
          KeReleaseInStackQueuedSpinLockFromDpcLevel(&v252);
        }
        NextEntryHashTable = RtlLookupEntryHashTable((PRTL_DYNAMIC_HASH_TABLE)(v39 + 16), v42, &Context);
        v45 = 0i64;
        if ( NextEntryHashTable )
        {
          v46 = 0i64;
          do
          {
            p_Blink = &NextEntryHashTable[-2].Linkage.Blink;
            if ( (__int64 *)NextEntryHashTable[-2].Signature == v11
              && (!*(_QWORD *)v223 || p_Blink[2] == *(struct _LIST_ENTRY **)v223)
              && !memcmp(p_Blink + 17, Buf2, v40)
              && (!v46 || *((_DWORD *)p_Blink + 16) > *(_DWORD *)(v46 + 64)) )
            {
              v46 = (__int64)p_Blink;
            }
            NextEntryHashTable = RtlGetNextEntryHashTable((PRTL_DYNAMIC_HASH_TABLE)(v39 + 16), &Context);
          }
          while ( NextEntryHashTable );
          v39 = v230;
          v217 = v46;
          v45 = v46;
          v94 = v46 == 0;
          v25 = v208;
          if ( !v94 )
          {
            if ( *(_DWORD *)(v45 + 4) == 1 )
            {
              v176 = *(_BYTE *)(v45 + 69);
              if ( (v176 & 1) == 0 && (v176 & 8) != 0 )
              {
                _InterlockedDecrement((volatile signed __int32 *)v11 + 77);
                _InterlockedDecrement((volatile signed __int32 *)(v11[42] + 56));
                if ( *((int *)v11 + 77) < 0 )
                  *((_DWORD *)v11 + 77) = 0;
                v177 = v11[42];
                if ( *(int *)(v177 + 56) < 0 )
                  *(_DWORD *)(v177 + 56) = 0;
              }
            }
            _InterlockedAdd((volatile signed __int32 *)(v45 + 4), 1u);
          }
        }
        _InterlockedDecrement((volatile signed __int32 *)(v39 + 8));
        v48 = *(_QWORD *)v223;
        if ( v45 || (v217 = IppCreateAndInitializeNeighbor(v11, *(_QWORD *)v223, Buf2, 1i64), (v45 = v217) != 0) )
        {
          *(_BYTE *)(v45 + 69) |= 2u;
          LOBYTE(v44) = 1;
          LOBYTE(AlignOffset) = 0;
          *(_QWORD *)v225 = IppUpdateNeighbor(v45, SpinLock, 0i64, v44, AlignOffset);
        }
        v49 = *(_QWORD *)(v48 + 8);
        if ( v220 >= 0x500 && v220 <= *(_DWORD *)(*(_QWORD *)(v48 + 40) + 8i64) )
        {
          *(_DWORD *)(v48 + 84) = v220;
          v50 = *(__int64 **)(v49 + 360);
          v51 = 0;
          while ( v50 != (__int64 *)(v49 + 360) )
          {
            if ( !v51 || *((_DWORD *)v50 + 5) < v51 )
              v51 = *((_DWORD *)v50 + 5);
            v50 = (__int64 *)*v50;
          }
          *(_DWORD *)(v49 + 376) = v51;
        }
        KeReleaseInStackQueuedSpinLockFromDpcLevel(&v253);
        v52 = *((_BYTE *)v11 + 401);
        if ( (v52 & 4) != 0 )
        {
          *((_BYTE *)v11 + 401) = v52 & 0xFB;
          Ipv6pResetAutoConfiguredSettings(v11, 8i64);
          v52 = *((_BYTE *)v11 + 401);
        }
        v53 = (v25 & 0x40) != 0;
        v54 = 0;
        v55 = 0;
        if ( v25 >> 7 != (v52 & 1) )
        {
          if ( (v25 & 0x80u) != 0 )
          {
            v54 = 1;
            v178 = (v25 >> 7) | v52 & 0xFE;
            *((_BYTE *)v11 + 401) = v178;
            if ( *((_DWORD *)&MICROSOFT_TCPIP_PROVIDER_Context + 9) == 1
              && ((__int64)WPP_MAIN_CB.Queue.Wcb.DmaWaitEntry.Blink & 4) != 0 )
            {
              McTemplateK0qsqqqq(
                (PMCGEN_TRACE_CONTEXT)&MICROSOFT_TCPIP_PROVIDER_Context,
                (__int64)"ManagedAddressConfiguration",
                v178 & 1,
                0,
                *(_DWORD *)*v11,
                *(_WORD *)(*(_QWORD *)(*v11 + 40) + 28i64));
            }
          }
          *(_DWORD *)(*v11 + 140) = 1;
        }
        v56 = v54;
        if ( v53 != ((*((_BYTE *)v11 + 401) & 2) != 0) )
        {
          if ( (v25 & 0x40) != 0 )
          {
            v55 = 1;
            v159 = *((_BYTE *)v11 + 401) & 0xFD | (2 * v53);
            v54 = 1;
            *((_BYTE *)v11 + 401) = v159;
            if ( *((_DWORD *)&MICROSOFT_TCPIP_PROVIDER_Context + 9) == 1
              && ((__int64)WPP_MAIN_CB.Queue.Wcb.DmaWaitEntry.Blink & 4) != 0 )
            {
              McTemplateK0qsqqqq(
                (PMCGEN_TRACE_CONTEXT)&MICROSOFT_TCPIP_PROVIDER_Context,
                (__int64)"OtherStatefulConfiguration",
                (v159 & 2) != 0,
                0,
                *(_DWORD *)*v11,
                *(_WORD *)(*(_QWORD *)(*v11 + 40) + 28i64));
            }
          }
          *(_DWORD *)(*v11 + 140) = 1;
        }
        v57 = v11[112];
        v265 = 0i64;
        v266 = 0i64;
        if ( !v57 )
          v57 = v11[113];
        if ( v57 )
        {
          if ( (v25 & 0x40) != 0 && v55 )
          {
            v249 = *((_OWORD *)v11 + 56);
            IppLocalitySetOtherStatefulAddressConfig(&v249, 0i64);
          }
          if ( (v25 & 0x80u) != 0 && v56 )
          {
            v250 = *((_OWORD *)v11 + 56);
            IppLocalitySetManagedAddressConfig(&v250, 0i64);
          }
        }
        if ( v54 )
        {
          v160 = (MEMORY[0xFFFFF78000000008] / 0x2710ui64 * (unsigned __int128)0x624DD2F1A9FBE77ui64) >> 64;
          v161 = v160 + ((MEMORY[0xFFFFF78000000008] / 0x2710ui64 - v160) >> 1);
          v162 = 1i64;
          v163 = v161 >> 8;
          if ( (_DWORD)v163 != -1 )
            v162 = (unsigned int)(v163 + 1);
          IppTimerUpdateNextExpirationTick(v163, v162);
          IppNotifyInterfaceChange((_DWORD)v11, 0, 0, 0, 3);
        }
        v58 = v222;
        if ( (v222 || (*(_DWORD *)(v11[5] + 36) & 2) == 0) && *(_DWORD *)v224 < 3u )
          *(_QWORD *)v224 = 0i64;
        if ( (unsigned __int8)NetioNcmFastCheckIsAoAcCapable() )
        {
          if ( *(_DWORD *)(v11[5] + 20) != 131 )
          {
            PoolWithTag = ExAllocatePoolWithTag((POOL_TYPE)512, 0x30ui64, 0x676E7049u);
            v180 = PoolWithTag;
            if ( PoolWithTag )
            {
              memset(PoolWithTag, 0, 0x30ui64);
              _InterlockedAdd((volatile signed __int32 *)v11 + 36, 1u);
              v180[2] = v11;
              v180[1] = IppActiveReferenceWorker;
              *((_BYTE *)v180 + 24) = 1;
              *((_DWORD *)v180 + 7) = 1;
              *((_DWORD *)v180 + 8) = 2;
              v180[5] = 0i64;
              NetioInsertWorkQueue(v11 + 30, v180);
            }
          }
        }
        if ( v219 && v219 != *((_DWORD *)v11 + 110) )
        {
          v181 = v219;
          *((_DWORD *)v11 + 110) = v219;
          *((_DWORD *)v11 + 111) = IppNeighborReachableTicks(v181);
        }
        KeReleaseInStackQueuedSpinLock(&LockHandle);
        if ( *(_QWORD *)v225 )
          IppFragmentPackets(&Ipv6Global, *(_QWORD *)v225);
        v59 = (__int64)v228;
        v60 = v228[4];
        if ( v60 )
          *((_BYTE *)v11 + 456) = v60;
        v61 = *(_DWORD *)(v59 + 12);
        if ( v61 )
        {
          v62 = _byteswap_ulong(v61);
          v63 = 2 * (unsigned __int64)v62 / 0x3E8;
          if ( !(_DWORD)v63 )
            LODWORD(v63) = v62 != 0;
          *((_DWORD *)v11 + 112) = v63;
        }
        v64 = 2 * v58;
        si128 = _mm_load_si128((const __m128i *)&_xmm);
        v65 = si128.m128i_u32[((unsigned __int64)v25 >> 3) & 3];
        if ( v65 == -1 )
          v65 = 256;
        v220 = v65;
        memset(v247, 255, sizeof(v247));
        v66 = v217;
        v247[1] = __PAIR64__(v65, v58);
        HIDWORD(v247[0]) = v58;
        LODWORD(v67) = 0;
        if ( v217 )
          v67 = *(_QWORD *)(v217 + 16);
        v68 = *v11;
        KeAcquireInStackQueuedSpinLock((PKSPIN_LOCK)v11 + 48, &v255);
        while ( *((_DWORD *)v11 + 98) )
          ;
        KeAcquireInStackQueuedSpinLockAtDpcLevel((PKSPIN_LOCK)(v68 + 192), &v254);
        v69 = NetBuffer;
        v70 = 0;
        if ( *(int *)(v68 + 200) >= 0 )
        {
          v71 = (_DWORD *)(v68 + 256);
          do
          {
            while ( *v71 )
              ;
            ++v70;
            v71 += 16;
          }
          while ( v70 <= *(_DWORD *)(v68 + 200) );
          v66 = v217;
        }
        v72 = *v11;
        if ( (int)IppValidateSetAllRouteParameters(
                    3 - (unsigned int)(v64 != 0),
                    (int)v11,
                    v67,
                    (int)&in6addr_any,
                    0,
                    0i64,
                    0,
                    3,
                    (__int64)v247,
                    Buf2,
                    0i64,
                    (__int64)&v237) >= 0 )
          IppCommitSetAllRouteParameters(3 - (v64 != 0), v72, v237, (unsigned int)&in6addr_any, 0, (__int64)v247);
        KeReleaseInStackQueuedSpinLockFromDpcLevel(&v254);
        KeReleaseInStackQueuedSpinLock(&v255);
        v73 = 16;
        v74 = v69->CurrentMdlOffset + 16;
        v213 = 16;
        if ( v74 >= *(_DWORD *)(v69->Link.Region + 40) )
        {
          NdisAdvanceNetBufferDataStart(v69, 0x10u, 0, 0i64);
        }
        else
        {
          v69->DataOffset += 16;
          v69->DataLength -= 16;
          v69->CurrentMdlOffset = v74;
        }
        while ( 1 )
        {
          v75 = v69->DataLength < 2;
          *(_WORD *)v229 = 0;
          if ( v75
            || (v76 = NdisGetDataBuffer(v69, 2u, v229, 1u, 0), v77 = 8 * (unsigned __int8)v76[1], (v214 = v77) == 0)
            || (v78 = v77, LODWORD(v228) = v77, v77 > v69->DataLength) )
          {
            v151 = v69->CurrentMdlOffset;
            v152 = v73;
            if ( v151 >= v73 )
            {
              v69->DataOffset -= v73;
              v69->DataLength += v73;
              v69->CurrentMdlOffset = v151 - v73;
            }
            else
            {
              NdisRetreatNetBufferDataStart(v69, v73, 0, NetioAllocateMdl);
            }
            if ( v215 )
            {
              v246 = 0i64;
              v244 = 1;
              v245 = 0i64;
              Ipv6pNotifyRouterInformationChange(v11, v152, &v244);
            }
            KeAcquireInStackQueuedSpinLock((PKSPIN_LOCK)v11 + 48, &LockHandle);
            while ( *((_DWORD *)v11 + 98) )
              ;
            v153 = v233;
            if ( (v11[50] & 2) == 0 && (*(_DWORD *)(v11[5] + 36) & 2) == 0 )
            {
              PotentialRouterUnderLock = Ipv6pFindPotentialRouterUnderLock(v11, v233[32]);
              if ( PotentialRouterUnderLock )
              {
                if ( !*(_DWORD *)(PotentialRouterUnderLock + 20) )
                {
                  *(_DWORD *)(PotentialRouterUnderLock + 16) = 3;
                  if ( v64 >= 0xE10 )
                    v200 = v64 >> 1;
                  else
                    v200 = 1800;
                  v201 = v235;
                  v202 = (unsigned int)(v235 + v200);
                  *(_DWORD *)(PotentialRouterUnderLock + 20) = v202;
                  if ( !(_DWORD)v202 )
                  {
                    *(_DWORD *)(PotentialRouterUnderLock + 20) = 1;
                    v202 = 1i64;
                  }
                  IppTimerUpdateNextExpirationTick(v201, v202);
                }
              }
            }
            KeReleaseInStackQueuedSpinLock(&LockHandle);
            result = v153[1];
            *(_DWORD *)(result + 140) = 0;
            if ( v66 )
            {
              v155 = *(_DWORD *)(v66 + 4);
              if ( v155 == 2 )
              {
                v155 = 2;
                if ( (*(_BYTE *)(v66 + 69) & 9) == 8 )
                {
                  _InterlockedAdd((volatile signed __int32 *)(*(_QWORD *)(v66 + 8) + 308i64), 1u);
                  _InterlockedAdd((volatile signed __int32 *)(*(_QWORD *)(*(_QWORD *)(v66 + 8) + 336i64) + 56i64), 1u);
                  v155 = *(_DWORD *)(v66 + 4);
                }
              }
              if ( v155 <= 0 )
                KeBugCheck(0x1Cu);
              result = (unsigned int)_InterlockedExchangeAdd((volatile signed __int32 *)(v66 + 4), 0xFFFFFFFF);
              if ( (_DWORD)result == 1 )
                return IppCleanupNeighbor(v66);
            }
            return result;
          }
          if ( *v76 == 3 )
            break;
          if ( *v76 == 24 )
          {
            v182 = (unsigned __int8 *)NdisGetDataBuffer(v69, v77, v271, 1u, 0);
            v274 = _mm_load_si128((const __m128i *)&_xmm);
            v183 = v274.m128i_u32[((unsigned __int64)v182[3] >> 3) & 3];
            v220 = v183;
            if ( v183 != -1 )
            {
              v184 = v182[2];
              v185 = _byteswap_ulong(*((_DWORD *)v182 + 1));
              v186 = 2 * v185;
              if ( (2 * v185) >> 1 != v185 )
                v186 = -1;
              CopyPrefix(v267, v182 + 8, v182[2], 16i64);
              IppUpdateAutoConfiguredRoute((_DWORD)v11, (_DWORD)Buf2, v66, (unsigned int)v267, v184, v186, v183);
              if ( v64 <= v186 )
                v186 = v64;
              v64 = v186;
              goto LABEL_241;
            }
LABEL_243:
            v73 = v213;
            goto LABEL_114;
          }
          if ( *v76 == 25 )
          {
            if ( (*((_BYTE *)v11 + 404) & 0x40) != 0 )
            {
              Ipv6pUpdateRDNSS(v11, v69, Buf2, (unsigned int)v235, &v215);
              goto LABEL_117;
            }
          }
          else if ( *v76 == 31 && (*((_BYTE *)v11 + 404) & 0x40) != 0 )
          {
            Ipv6pUpdateDNSSL(v11, v69, Buf2, (unsigned int)v235, &v215);
            goto LABEL_117;
          }
LABEL_114:
          if ( v78 )
          {
            v79 = v78 + v69->CurrentMdlOffset;
            if ( v79 >= *(_DWORD *)(v69->Link.Region + 40) )
            {
              NdisAdvanceNetBufferDataStart(v69, v78, 0, 0i64);
            }
            else
            {
              v69->DataOffset += v78;
              v69->DataLength -= v78;
              v69->CurrentMdlOffset = v79;
            }
          }
LABEL_117:
          v73 += v77;
          v213 = v73;
        }
        memset(v269, 0, sizeof(v269));
        v80 = NdisGetDataBuffer(v69, v77, v269, 1u, 0);
        v240 = v80;
        v82 = _byteswap_ulong(*((_DWORD *)v80 + 1));
        v83 = *((_BYTE *)v80 + 2);
        v212 = v83;
        v81 = v83;
        v222 = v83;
        v84 = 2 * v82;
        v85 = _byteswap_ulong(*((_DWORD *)v80 + 2));
        if ( (2 * v82) >> 1 != v82 )
          v84 = -1;
        v221 = v84;
        v86 = 2 * v85;
        v94 = (2 * v85) >> 1 == v85;
        v87 = v259;
        if ( !v94 )
          v86 = -1;
        LODWORD(v230) = v86;
        v88 = v86;
        if ( v64 <= v86 )
          v88 = v64;
        v89 = v83 >> 3;
        v64 = v88;
        v219 = v88;
        v90 = 0;
        v91 = v83 & 7;
        do
        {
          if ( v90 >= (unsigned int)v89 )
            v92 = 0;
          else
            v92 = *((_BYTE *)v87 + (_BYTE *)v80 + 16 - (_BYTE *)v259);
          *(_BYTE *)v87 = v92;
          ++v90;
          v87 = (int *)((char *)v87 + 1);
        }
        while ( v90 < 0x10 );
        if ( v91 )
          *((_BYTE *)v259 + v89) = *((_BYTE *)v80 + v89 + 16) & (-1 << (8 - v91));
        v93 = v259[0];
        if ( LOBYTE(v259[0]) == 0xFE )
          v94 = (BYTE1(v259[0]) & 0xC0) == 0x80;
        else
          v94 = LOBYTE(v259[0]) == 0xFF;
        if ( v94 )
        {
          v66 = v217;
LABEL_242:
          v77 = v214;
          goto LABEL_243;
        }
        v95 = *((_BYTE *)v80 + 3);
        if ( v95 < 0 && ((*((_BYTE *)v11 + 404) & 1) == 0 || v212 != 64) )
        {
          v96 = -(v84 != 0);
          memset(v248, 255, 0x20ui64);
          v97 = -1;
          if ( v84 != -1 )
            v97 = v84 >> 1;
          v98 = *v11;
          v248[1] = __PAIR64__(v220, v97);
          HIDWORD(v248[0]) = v97;
          KeAcquireInStackQueuedSpinLock((PKSPIN_LOCK)v11 + 48, &v257);
          while ( *((_DWORD *)v11 + 98) )
            ;
          KeAcquireInStackQueuedSpinLockAtDpcLevel((PKSPIN_LOCK)(v98 + 192), &v256);
          v69 = NetBuffer;
          v99 = 0;
          if ( *(int *)(v98 + 200) >= 0 )
          {
            v100 = (_DWORD *)(v98 + 256);
            do
            {
              while ( *v100 )
                ;
              ++v99;
              v100 += 16;
            }
            while ( v99 <= *(_DWORD *)(v98 + 200) );
            v69 = NetBuffer;
          }
          v101 = *v11;
          if ( (int)IppValidateSetAllRouteParameters(
                      v96 + 3,
                      (int)v11,
                      0,
                      (int)v259,
                      v212,
                      0i64,
                      0,
                      3,
                      (__int64)v248,
                      0i64,
                      0i64,
                      (__int64)&v238) >= 0 )
            IppCommitSetAllRouteParameters(v96 + 3, v101, v238, (unsigned int)v259, v212, (__int64)v248);
          KeReleaseInStackQueuedSpinLockFromDpcLevel(&v256);
          KeReleaseInStackQueuedSpinLock(&v257);
          v95 = *((_BYTE *)v80 + 3);
          v93 = v259[0];
          v84 = v221;
        }
        if ( (v95 & 1) != 0 )
        {
          IppUpdateAutoConfiguredRoute((_DWORD)v11, (_DWORD)Buf2, v217, (unsigned int)v259, v212, v84, v220);
          v93 = v259[0];
        }
        if ( v93 == -2 && (BYTE1(v259[0]) & 0xC0) == 0xC0 )
        {
LABEL_189:
          if ( (*((_BYTE *)v80 + 3) & 0x40) != 0 )
          {
            v125 = v221;
            if ( (unsigned int)v230 > v221 )
            {
              if ( WPP_GLOBAL_Control != (PDEVICE_OBJECT)&WPP_GLOBAL_Control
                && BYTE1(WPP_GLOBAL_Control->Timer) >= 3u
                && (HIDWORD(WPP_GLOBAL_Control->Timer) & 0x40) != 0 )
              {
                WPP_SF_(WPP_GLOBAL_Control->AttachedDevice, 10i64, &WPP_57de0b8e867d3f78f25340b31d452f46_Traceguids);
              }
            }
            else
            {
              v126 = v81;
              v127 = *(unsigned __int8 *)(v11[5] + 11);
              if ( v127 + v81 == 128 )
              {
                if ( (*((_BYTE *)v11 + 404) & 1) != 0 && v81 == 64 )
                {
                  LOBYTE(v91) = 64;
                  Ipv6pUpdateSitePrefix(1, (_DWORD)v11, (unsigned int)v259, v91, v221, v230);
                  goto LABEL_239;
                }
                KeAcquireInStackQueuedSpinLock((PKSPIN_LOCK)v11 + 48, &v258);
                LOBYTE(FreeRoutine) = 0;
                while ( *((_DWORD *)v11 + 98) )
                  ;
                v129 = 1;
                v210 = 1;
                LODWORD(v224) = *(unsigned __int8 *)(v11[5] + 11);
                memset(DeleteCount, 0, sizeof(DeleteCount));
                v130 = (PRTL_AVL_TABLE *)(v11 + 75);
                while ( 1 )
                {
LABEL_199:
                  if ( v11[76] )
                  {
                    v131 = *(PRTL_AVL_TABLE **)&DeleteCount[2];
                    if ( !*(_QWORD *)&DeleteCount[2] )
                      v131 = (PRTL_AVL_TABLE *)*v130;
                    if ( v131 == v130 )
                      *(_QWORD *)&DeleteCount[2] = 0i64;
                    else
                      *(_QWORD *)&DeleteCount[2] = *v131;
                    v132 = 0i64;
                    if ( v131 != v130 )
                      v132 = v131;
                  }
                  else
                  {
                    AllocateRoutine_low = LODWORD((*v130)->AllocateRoutine);
                    FreeRoutine = (unsigned int)(*v130)->FreeRoutine;
                    v191 = (char *)RtlEnumerateGenericTableLikeADirectory(
                                     *v130,
                                     0i64,
                                     0i64,
                                     1u,
                                     (PVOID *)&DeleteCount[2],
                                     DeleteCount,
                                     (char *)&DeleteCount[4] - AllocateRoutine_low);
                    v192 = v191;
                    if ( !v191 )
                    {
LABEL_237:
                      v69 = NetBuffer;
                      if ( v129 )
                      {
                        if ( v125 )
                        {
                          v263 = *(_OWORD *)v259;
                          memmove((char *)&v264 - ((unsigned int)v224 >> 3), v11 + 66, (unsigned int)v224 >> 3);
                          v168 = v222;
                          LOBYTE(v207) = 0;
                          LOBYTE(v206) = 0;
                          LOBYTE(AlignOffseta) = 68;
                          if ( (int)IppFindOrCreateLocalAddress(
                                      *(_QWORD *)(*v11 + 40),
                                      &v263,
                                      1i64,
                                      v11,
                                      AlignOffseta,
                                      v230,
                                      v221,
                                      v222,
                                      v206,
                                      0i64,
                                      v207,
                                      0i64,
                                      &v234) >= 0 )
                          {
                            v169 = v234;
                            memmove(
                              (char *)v234 + 172,
                              Buf2,
                              *(unsigned __int16 *)(*(_QWORD *)(*(_QWORD *)(*v11 + 40) + 16i64) + 6i64));
                            IppDereferenceLocalAddress(v169);
                            if ( (v11[50] & 2) != 0 )
                            {
                              CopyPrefix(v268, v259, v168, 16i64);
                              LOBYTE(v207) = 0;
                              LOBYTE(v206) = 0;
                              LOBYTE(AlignOffsetb) = 68;
                              if ( (int)IppFindOrCreateLocalAddress(
                                          *(_QWORD *)(*v11 + 40),
                                          v268,
                                          2i64,
                                          v11,
                                          AlignOffsetb,
                                          -1,
                                          -1,
                                          8
                                        * (unsigned int)*(unsigned __int16 *)(*(_QWORD *)(*(_QWORD *)(*v11 + 40) + 16i64)
                                                                            + 6i64),
                                          v206,
                                          0i64,
                                          v207,
                                          0i64,
                                          &v241) >= 0 )
                                IppDereferenceLocalAddress(v241);
                            }
                            if ( (LOBYTE(v259[0]) != 0xFE || (BYTE1(v259[0]) & 0xC0) != 0xC0)
                              && (int)IppCreateLocalTemporaryAddress(
                                        (unsigned int)v259,
                                        (_DWORD)v11,
                                        (_DWORD)v169,
                                        v170,
                                        (__int64)&v242) >= 0 )
                            {
                              IppDereferenceLocalAddress(v242);
                            }
                          }
                        }
                      }
                      KeReleaseInStackQueuedSpinLock(&v258);
                      goto LABEL_239;
                    }
                    memmove(&DeleteCount[4], &v191[AllocateRoutine_low], FreeRoutine);
                    LOBYTE(FreeRoutine) = 0;
                    v132 = (PRTL_AVL_TABLE *)(v192 - 32);
                    v126 = v222;
                  }
                  if ( !v132 )
                    goto LABEL_237;
                  v133 = (PKSPIN_LOCK)(v132 - 9);
                  SpinLock = (PKSPIN_LOCK)(v132 - 9);
                  v234 = v132 - 9;
                  if ( !*((_DWORD *)v132 + 8) )
                    goto LABEL_198;
                  v134 = v126;
                  v135 = v259;
                  v136 = *(char **)v133[2];
                  if ( v126 > 8 )
                    break;
LABEL_211:
                  if ( v134 && (unsigned __int8)*v136 >> (8 - v134) != *(_BYTE *)v135 >> (8 - v134)
                    || (*((_DWORD *)v133 + 15) & 0xF0) != 64 )
                  {
                    goto LABEL_198;
                  }
                  v139 = (__int64)v234;
                  v140 = *((_DWORD *)v234 + 36);
                  v141 = *((_DWORD *)v234 + 35);
                  v142 = (MEMORY[0xFFFFF78000000008] / 0x2710ui64 * (unsigned __int128)0x624DD2F1A9FBE77ui64) >> 64;
                  *(_DWORD *)v229 = v140;
                  v143 = (v142 + ((MEMORY[0xFFFFF78000000008] / 0x2710ui64 - v142) >> 1)) >> 8;
                  *(_DWORD *)v225 = *((_DWORD *)v234 + 37);
                  v144 = v143 - *(_DWORD *)v225;
                  *(_QWORD *)v223 = v143;
                  v145 = -1;
                  if ( v140 == -1 )
                  {
                    v146 = -1;
                  }
                  else if ( v144 >= v140 )
                  {
                    v146 = 0;
                  }
                  else
                  {
                    v146 = v140 - v144;
                  }
                  *((_DWORD *)v234 + 36) = v146;
                  if ( v141 != -1 )
                  {
                    if ( v144 >= v141 )
                      v145 = 0;
                    else
                      v145 = v141 - v144;
                  }
                  *(_DWORD *)(v139 + 140) = v145;
                  v147 = v145;
                  *(_DWORD *)(v139 + 148) = v143;
                  if ( (BYTE4(WPP_MAIN_CB.Queue.Wcb.DmaWaitEntry.Flink) & 2) != 0 )
                  {
                    v193 = *(_BYTE **)(v139 + 8);
                    v194 = *(_QWORD *)(*(_QWORD *)v193 + 40i64);
                    if ( (char *)v194 == &Ipv4Global )
                    {
                      v195 = 0;
                      v196 = 4;
                      v197 = *(unsigned int **)v133[2];
                      v198 = 0i64;
                      FreeRoutine = *v197;
                    }
                    else
                    {
                      v196 = 6;
                      v195 = *(unsigned __int16 *)(*(_QWORD *)(v194 + 16) + 6i64);
                      v198 = *(_QWORD *)v133[2];
                    }
                    v147 = v145;
                    if ( *((_DWORD *)&MICROSOFT_TCPIP_PROVIDER_Context + 9) == 1
                      && (!TcpipTraceFiltersExist || (v193[404] & 2) != 0) )
                    {
                      McTemplateK0qsqqbr2qqqqqqqq(
                        (PMCGEN_TRACE_CONTEXT)&MICROSOFT_TCPIP_PROVIDER_Context,
                        *(_QWORD *)(v194 + 8),
                        v195,
                        FreeRoutine,
                        v198,
                        v196,
                        v223[0],
                        v225[0],
                        v141,
                        v229[0],
                        v223[0],
                        v145,
                        v146);
                      v147 = *(_DWORD *)(v139 + 140);
                    }
                    LODWORD(v143) = *(_DWORD *)v223;
                    LOBYTE(FreeRoutine) = 0;
                    v133 = SpinLock;
                  }
                  v125 = v221;
                  if ( v221 > 0x3840 || v221 > v147 )
                  {
                    *(_DWORD *)(v139 + 140) = v221;
                    v147 = v125;
                  }
                  else if ( v147 > 0x3840 )
                  {
                    *(_DWORD *)(v139 + 140) = 14400;
                    v147 = 14400;
                  }
                  v94 = *((_BYTE *)v133 + 60) == 69;
                  v148 = v230;
                  v149 = v230;
                  *(_DWORD *)(v139 + 144) = v230;
                  if ( v94 )
                  {
                    v156 = v143 - *(_DWORD *)(v139 + 152);
                    v157 = dword_1C01FB510;
                    if ( v147 > dword_1C01FB50C || (v158 = v147, v156 > dword_1C01FB50C - v147) )
                    {
                      if ( dword_1C01FB50C <= v156 )
                      {
                        *(_DWORD *)(v139 + 140) = 0;
                        v158 = 0;
                      }
                      else
                      {
                        v158 = dword_1C01FB50C - v156;
                        *(_DWORD *)(v139 + 140) = dword_1C01FB50C - v156;
                      }
                    }
                    if ( v148 > v157 || (v147 = v158, v149 = v148, v156 > v157 - v148) )
                    {
                      v147 = v158;
                      if ( v157 <= v156 )
                      {
                        *(_DWORD *)(v139 + 144) = 0;
                        v149 = 0;
                      }
                      else
                      {
                        v149 = v157 - v156;
                        *(_DWORD *)(v139 + 144) = v157 - v156;
                      }
                    }
                  }
                  v150 = *(_DWORD *)(v139 + 144);
                  if ( v147 < v149 )
                    v150 = v147;
                  *(_DWORD *)(v139 + 144) = v150;
                  IppHandleAddressLifetimeTimeout(v139, (unsigned int)v143);
                  if ( *(_DWORD *)(v139 + 140)
                    && (memmove(
                          (void *)(v139 + 172),
                          Buf2,
                          *(unsigned __int16 *)(*(_QWORD *)(*(_QWORD *)(*v11 + 40) + 16i64) + 6i64)),
                        *((_BYTE *)v133 + 60) == 68) )
                  {
                    v129 = 0;
                    v210 = 0;
                  }
                  else
                  {
                    v129 = v210;
                  }
                  v126 = v222;
                }
                while ( 1 )
                {
                  v137 = *v136++;
                  v138 = *(_BYTE *)v135;
                  v135 = (int *)((char *)v135 + 1);
                  if ( v137 != v138 )
                    break;
                  v134 -= 8;
                  if ( v134 <= 8 )
                    goto LABEL_211;
                }
LABEL_198:
                v129 = v210;
                goto LABEL_199;
              }
              if ( WPP_GLOBAL_Control != (PDEVICE_OBJECT)&WPP_GLOBAL_Control
                && BYTE1(WPP_GLOBAL_Control->Timer) >= 3u
                && (HIDWORD(WPP_GLOBAL_Control->Timer) & 0x40) != 0 )
              {
                WPP_SF_Dd(
                  WPP_GLOBAL_Control->AttachedDevice,
                  11i64,
                  &WPP_57de0b8e867d3f78f25340b31d452f46_Traceguids,
                  v81,
                  v127);
              }
            }
LABEL_239:
            v64 = v219;
          }
          v66 = v217;
LABEL_241:
          v78 = (unsigned int)v228;
          goto LABEL_242;
        }
        v102 = *((_BYTE *)v80 + 3);
        if ( (v102 & 0x10) != 0 )
        {
          v103 = *((_BYTE *)v80 + 15);
        }
        else
        {
          if ( (v102 & 0x40) == 0 )
          {
            v103 = 0;
            v209 = 0;
            goto LABEL_154;
          }
          v103 = *((_BYTE *)v11 + 458);
        }
        v209 = v103;
LABEL_154:
        if ( !v103 || v103 > v212 )
          goto LABEL_188;
        v104 = *v11;
        v105 = 0;
        v106 = 0i64;
        v218 = 1;
        v107 = v103 >> 3;
        *(_QWORD *)v225 = v104;
        do
        {
          if ( v105 >= (unsigned int)v107 )
            *((_BYTE *)&DeleteCount[-4] + v106) = 0;
          else
            *((_BYTE *)&DeleteCount[-4] + v106) = *((_BYTE *)v259 + v106);
          ++v105;
          ++v106;
        }
        while ( v105 < 0x10 );
        if ( (v103 & 7) != 0 )
          *((_BYTE *)&DeleteCount[-4] + v107) = *((_BYTE *)v259 + v107) & (-1 << (8 - (v103 & 7)));
        v108 = (PKSPIN_LOCK)(v104 + 640);
        SpinLock = (PKSPIN_LOCK)(v104 + 640);
        NewIrql = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(v104 + 640));
        v109 = (char *)(v104 + 648);
        v110 = 0;
        v224 = (char *)(v104 + 648);
        v111 = *(char **)(v104 + 648);
        v112 = MEMORY[0xFFFFF78000000008] / 0x2710ui64 / 0x1F4;
        *(_QWORD *)v223 = v112;
        if ( v111 != (char *)(v104 + 648) )
        {
          v113 = v218;
          do
          {
            v114 = v110;
            v239 = *(char **)v111;
            if ( *((__int64 **)v111 + 2) == v11
              && *(_OWORD *)(v111 + 38) == v260
              && v111[36] == v103
              && *((_DWORD *)v111 + 14) == v110 )
            {
              v113 = v110;
              *((_DWORD *)v111 + 7) = v221;
              v114 = 1;
              *((_DWORD *)v111 + 8) = v230;
              *((_DWORD *)v111 + 6) = v112;
            }
            v115 = *((_DWORD *)v111 + 7);
            if ( v115 == -1 )
            {
              v117 = -1;
            }
            else
            {
              v116 = v112 - *((_DWORD *)v111 + 6);
              if ( v116 >= v115 )
                v117 = v110;
              else
                v117 = v115 - v116;
            }
            v118 = *((_DWORD *)v111 + 8);
            *((_DWORD *)v111 + 7) = v117;
            if ( v118 == -1 )
            {
              v120 = -1;
            }
            else
            {
              v119 = v112 - *((_DWORD *)v111 + 6);
              if ( v119 >= v118 )
                v120 = v110;
              else
                v120 = v118 - v119;
            }
            *((_DWORD *)v111 + 6) = v112;
            if ( v120 > v117 )
              v120 = v117;
            *((_DWORD *)v111 + 8) = v120;
            if ( v117 )
            {
              v121 = (unsigned int)(v112 + v117);
              if ( v117 > 0 )
              {
                if ( (_DWORD)v121 )
                {
                  v122 = *(_DWORD *)(v104 + 672);
                  if ( !v122 || (int)v121 - v122 < 0 )
                  {
                    *(_DWORD *)(v104 + 672) = v121;
                    IppTimerUpdateNextExpirationTick((unsigned int)v112, v121);
                    v109 = v224;
                    v110 = 0;
                  }
                }
              }
              if ( v114 )
              {
                v123 = (volatile signed __int32 *)*((_QWORD *)v111 + 2);
                v124 = *(_QWORD *)(*(_QWORD *)v123 + 40i64);
                if ( *((_DWORD *)v111 + 14) == 1 && (unsigned __int8)RoReferenceEx(v124 + 17432) )
                {
                  v187 = *(_QWORD *)(v124 + 17424);
                  if ( (unsigned __int8)RoReferenceEx(v187 + 304) )
                  {
                    v188 = (char *)ExAllocatePoolWithTag((POOL_TYPE)512, 0x78ui64, 0x746E5049u);
                    v189 = v188;
                    if ( v188 )
                    {
                      memset(v188, 0, 0x38ui64);
                      *((_QWORD *)v189 + 1) = IppNotifySitePrefixChangeAtPassive;
                      *((_QWORD *)v189 + 2) = v189 + 56;
                      *((_DWORD *)v189 + 6) = 0;
                      _InterlockedIncrement(v123 + 36);
                      *(_OWORD *)(v189 + 56) = *(_OWORD *)v111;
                      *(_OWORD *)(v189 + 72) = *((_OWORD *)v111 + 1);
                      *(_OWORD *)(v189 + 88) = *((_OWORD *)v111 + 2);
                      *(_OWORD *)(v189 + 104) = *((_OWORD *)v111 + 3);
                      NetioInsertWorkQueue(*(_QWORD *)v123 + 80i64, v189);
                    }
                    else
                    {
                      if ( _InterlockedExchangeAdd((volatile signed __int32 *)(v187 + 304), 0xFFFFFFFE) == 3 )
                        KeSetEvent((PRKEVENT)(v187 + 312), 0, 0);
                      IppDereferenceNsiClientContext(v124);
                      if ( *((_DWORD *)&MICROSOFT_TCPIP_PROVIDER_Context + 9) == 1
                        && (BYTE3(WPP_MAIN_CB.Queue.Wcb.DmaWaitEntry.Flink) & 8) != 0 )
                      {
                        McTemplateK0z((PMCGEN_TRACE_CONTEXT)&MICROSOFT_TCPIP_PROVIDER_Context);
                      }
                    }
                  }
                  else
                  {
                    IppDereferenceNsiClientContext(v124);
                  }
                  v109 = v224;
                  v110 = 0;
                  LODWORD(v112) = *(_DWORD *)v223;
                }
                v104 = *(_QWORD *)v225;
                v103 = v209;
              }
            }
            else
            {
              IppRemoveSitePrefixEntry(v111);
              v109 = v224;
              v110 = 0;
            }
            v111 = v239;
          }
          while ( v239 != v109 );
          v94 = v113 == 0;
          v69 = NetBuffer;
          if ( v94 )
            goto LABEL_187;
          v108 = SpinLock;
        }
        v164 = v221;
        if ( v221 )
        {
          if ( !(*(_BYTE *)(*(_QWORD *)(*v11 + 40) + 17618i64) == (_BYTE)v110 ? v110 : *((_DWORD *)v11 + 130) >= 0xAu) )
          {
            v166 = (char *)ExAllocatePoolWithTag((POOL_TYPE)512, 0x40ui64, 0x676E7049u);
            if ( v166 )
            {
              _InterlockedIncrement((volatile signed __int32 *)v11 + 36);
              v167 = v260;
              *((_DWORD *)v166 + 8) = v230;
              *((_DWORD *)v166 + 14) = 0;
              *(_OWORD *)(v166 + 38) = v167;
              *((_QWORD *)v166 + 2) = v11;
              *((_DWORD *)v166 + 6) = v112;
              *((_DWORD *)v166 + 7) = v164;
              v166[36] = v103;
              IppAddSitePrefixEntry(v108, v166);
            }
            else if ( *((_DWORD *)&MICROSOFT_TCPIP_PROVIDER_Context + 9) == 1
                   && (BYTE3(WPP_MAIN_CB.Queue.Wcb.DmaWaitEntry.Flink) & 8) != 0 )
            {
              McTemplateK0z((PMCGEN_TRACE_CONTEXT)&MICROSOFT_TCPIP_PROVIDER_Context);
            }
          }
        }
LABEL_187:
        KeReleaseSpinLock(SpinLock, NewIrql);
        v64 = v219;
        v80 = v240;
LABEL_188:
        v81 = v212;
        goto LABEL_189;
      }
      v174 = Ipv6pFindPotentialRouterUnderLock(v11, v36[32]);
      if ( v174 )
      {
        v94 = *(_DWORD *)(v174 + 24) == 5;
        v224 = (char *)(v174 + 16);
        *(_BYTE *)(v174 + 28) = v175;
        if ( !v94 )
        {
          *(_DWORD *)(v174 + 24) = 5;
          Ipv6NotifyPotentialRouterChange(v11, v174);
        }
        goto LABEL_44;
      }
    }
    KeReleaseInStackQueuedSpinLock(&LockHandle);
    result = v36[1];
    *(_DWORD *)(result + 140) = 0;
    return result;
  }
  if ( *a3 == 28 )
    *a3 = 27;
  result = v233[1];
  *(_DWORD *)(result + 140) = -1073741285;
  return result;
}