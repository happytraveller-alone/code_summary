__int64 __fastcall VmsNblHelperCreateCloneNbl(
        PNET_BUFFER_LIST NetBufferList,
        void *a2,
        void *a3,
        char a4,
        char a5,
        char a6,
        NET_BUFFER_FREE_MDL_HANDLER FreeMdlHandler,
        struct _NET_BUFFER_LIST **a8)
{
  void **v9; // r8
  __int64 v10; // rdi
  _QWORD *v11; // rax
  unsigned __int8 v12; // bl
  __int64 v13; // rax
  __int64 v14; // rax
  unsigned __int64 v15; // rax
  void *v16; // rsp
  ULONG CurrentProcessorNumber; // eax
  void *v18; // rbx
  int v19; // esi
  struct _NET_BUFFER_LIST *v20; // rdi
  char v21; // r12
  int v22; // r15d
  char v23; // r13
  struct _NET_BUFFER_LIST *CloneNetBufferList; // rax
  int v25; // edx
  NDIS_STATUS NetBufferListContext; // esi
  _DWORD *v27; // rcx
  unsigned __int16 v28; // bx
  char v29; // si
  __int64 v30; // rdx
  NDIS_STATUS v31; // r9d
  int v32; // ecx
  int v33; // ecx
  int v34; // ecx
  _QWORD *v36; // rax
  __int64 v37; // rax
  _QWORD *v38; // rax
  __int64 v39; // rax
  ULONG v40; // r12d
  NDIS_STATUS v41; // eax
  int v42; // edx
  _NET_BUFFER *Alignment; // r12
  struct _NET_BUFFER *v44; // r13
  int v45; // r9d
  _NET_BUFFER *FirstNetBuffer; // rsi
  int v47; // r15d
  ULONG v48; // r12d
  unsigned int DataLength; // r13d
  _WORD *DataBuffer; // rax
  __int16 v51; // ax
  unsigned int v52; // ecx
  unsigned __int16 v53; // ax
  unsigned int v54; // r13d
  int v55; // eax
  unsigned int CurrentMdlOffset; // eax
  _BYTE *v57; // rax
  _BYTE *v58; // rax
  __int16 v59; // ax
  unsigned int v60; // ecx
  char v61[4]; // [rsp+50h] [rbp+0h] BYREF
  int v62; // [rsp+54h] [rbp+4h]
  char v63; // [rsp+58h] [rbp+8h]
  char v64; // [rsp+59h] [rbp+9h]
  char v65; // [rsp+5Ah] [rbp+Ah]
  char v66; // [rsp+5Bh] [rbp+Bh]
  ULONG BytesCopied; // [rsp+5Ch] [rbp+Ch] BYREF
  __int64 v68; // [rsp+60h] [rbp+10h]
  NDIS_HANDLE NetBufferPoolHandle; // [rsp+68h] [rbp+18h]
  NDIS_HANDLE NetBufferListPoolHandle; // [rsp+70h] [rbp+20h]
  struct _NET_BUFFER_LIST **v71; // [rsp+78h] [rbp+28h]
  __int64 v72[17]; // [rsp+80h] [rbp+30h] BYREF
  char v73[4]; // [rsp+110h] [rbp+C0h] BYREF
  int v74; // [rsp+114h] [rbp+C4h]
  ULONG v75; // [rsp+118h] [rbp+C8h]
  __int64 v76; // [rsp+11Ch] [rbp+CCh]
  __int64 v77; // [rsp+128h] [rbp+D8h]
  __int64 *v78; // [rsp+130h] [rbp+E0h]
  char v79; // [rsp+138h] [rbp+E8h]
  int v80; // [rsp+13Ch] [rbp+ECh]
  __int64 v81; // [rsp+140h] [rbp+F0h]
  __int64 v82; // [rsp+148h] [rbp+F8h] BYREF
  int v83; // [rsp+150h] [rbp+100h]
  int v84; // [rsp+154h] [rbp+104h]
  char *v85; // [rsp+158h] [rbp+108h]
  __int128 *v86; // [rsp+160h] [rbp+110h]
  __int64 Storage; // [rsp+170h] [rbp+120h] BYREF
  void *retaddr; // [rsp+1B8h] [rbp+168h]

  NetBufferPoolHandle = a3;
  NetBufferListPoolHandle = a2;
  v71 = a8;
  v66 = a4;
  memset(v72, 0, sizeof(v72));
  v9 = 0i64;
  if ( (VmsDiagnosticFlags & 1) != 0 )
  {
    if ( NetBufferList )
    {
      v36 = NetBufferList->NetBufferListInfo[18];
      if ( v36 )
      {
        v37 = v36[2];
        if ( v37 )
        {
          *(_DWORD *)(v37 + 176) = 389;
          *(_QWORD *)(v37 + 168) = "VmsNblHelperCreateCloneNbl";
          *(_QWORD *)(v37 + 160) = retaddr;
        }
      }
    }
  }
  v10 = 4i64;
  if ( byte_1C019CD30 )
    v10 = (unsigned int)dword_1C019CD10;
  if ( (VmsDiagnosticFlags & 1) != 0 )
  {
    if ( NetBufferList )
    {
      v38 = NetBufferList->NetBufferListInfo[18];
      if ( v38 )
      {
        v39 = v38[2];
        if ( v39 )
        {
          *(_DWORD *)(v39 + 176) = 75;
          *(_QWORD *)(v39 + 168) = "VmsNblIsSourceNicUntrusted";
          *(_QWORD *)(v39 + 160) = retaddr;
        }
      }
    }
  }
  v11 = NetBufferList->NetBufferListInfo[18];
  v12 = 0;
  if ( v11 )
  {
    v13 = v11[2];
    if ( v13 )
    {
      v14 = *(_QWORD *)(v13 + 16);
      if ( v14 )
      {
        if ( *(_DWORD *)(v14 + 1880) != 3 || (v12 = 1, *(_BYTE *)(v14 + 1885)) )
          v12 = 0;
      }
    }
  }
  v15 = 24 * v10 + 15;
  if ( v15 <= 24 * v10 )
    v15 = 0xFFFFFFFFFFFFFF0i64;
  v16 = alloca(v15 & 0xFFFFFFFFFFFFFFF0ui64);
  if ( v12 != 1 || qword_1C019CD20 )
  {
    CurrentProcessorNumber = KeGetCurrentProcessorNumberEx(0i64);
    v9 = 0i64;
    v76 = 1i64;
    v75 = CurrentProcessorNumber;
    v73[0] = 0;
    v77 = 0i64;
    v81 = 0i64;
    v80 = 0;
    v74 = v12 | (qword_1C019CD20 != 0 ? 4 : 0);
    v78 = &v82;
    v79 = 0;
    v82 = 0i64;
    v83 = 0;
    if ( v61 )
    {
      v84 = v10;
      v85 = v61;
    }
    else
    {
      v84 = 0;
      v85 = 0i64;
    }
    v86 = &g_BatchLibContext;
  }
  v18 = NetBufferList->NetBufferListInfo[0];
  LOWORD(v19) = 0;
  v68 = 0i64;
  v65 = 0;
  v20 = 0i64;
  v62 = 0;
  v63 = 0;
  v21 = v18 != 0i64 ? a6 : 0;
  LOWORD(v22) = 0;
  v64 = v21;
  if ( !v21 )
  {
    v23 = 0;
    goto LABEL_18;
  }
  if ( ((unsigned __int8)v18 & 4) != 0 )
  {
    v22 = WORD1(v18) & 0x3FF;
    v19 = v22 + 20;
    goto LABEL_67;
  }
  if ( ((unsigned __int8)v18 & 8) == 0 )
  {
    v19 = 34;
    goto LABEL_67;
  }
  FirstNetBuffer = NetBufferList->FirstNetBuffer;
  HIDWORD(v68) = 70;
  v47 = 0;
  v48 = 0;
  Storage = 0i64;
  DataLength = FirstNetBuffer->DataLength;
  if ( DataLength < 0xE )
    goto LABEL_94;
  DataBuffer = NdisGetDataBuffer(FirstNetBuffer, 0xEu, 0i64, 1u, 0);
  v9 = 0i64;
  if ( !DataBuffer )
    goto LABEL_86;
  v72[0] = (__int64)FirstNetBuffer;
  v48 = 14;
  HIDWORD(v72[2]) = FirstNetBuffer->DataLength;
  v72[1] = (__int64)DataBuffer;
  LODWORD(v72[3]) = DataLength;
  v51 = DataBuffer[6];
  HIDWORD(v72[14]) += 14;
  LODWORD(v72[15]) += 14;
  WORD1(v72[2]) = __ROR2__(v51, 8);
  v52 = FirstNetBuffer->CurrentMdlOffset + 14;
  if ( v52 >= *(_DWORD *)(FirstNetBuffer->Link.Region + 40) )
  {
    NdisAdvanceNetBufferDataStart(FirstNetBuffer, 0xEu, 0, 0i64);
    v9 = 0i64;
  }
  else
  {
    FirstNetBuffer->DataOffset += 14;
    FirstNetBuffer->DataLength -= 14;
    FirstNetBuffer->CurrentMdlOffset = v52;
  }
  v53 = WORD1(v72[2]);
  if ( WORD1(v72[2]) <= 0x600u )
  {
    if ( WORD1(v72[2]) < 2u )
      goto LABEL_60;
    if ( DataLength >= 0x10 )
    {
      v57 = NdisGetDataBuffer(FirstNetBuffer, 2u, &Storage, 1u, 0);
      v9 = 0i64;
      if ( !v57 )
        goto LABEL_86;
      if ( *v57 != 0xAA || v57[1] != 0xAA )
        goto LABEL_60;
      if ( DataLength >= 0x16 )
      {
        v58 = NdisGetDataBuffer(FirstNetBuffer, 8u, &Storage, 1u, 0);
        if ( v58 )
        {
          if ( v58[2] != 3 )
            goto LABEL_60;
          v59 = *((_WORD *)v58 + 3);
          LODWORD(v72[15]) += 8;
          WORD1(v72[2]) = __ROR2__(v59, 8);
          v48 = 22;
          v60 = FirstNetBuffer->CurrentMdlOffset + 8;
          if ( v60 >= *(_DWORD *)(FirstNetBuffer->Link.Region + 40) )
          {
            NdisAdvanceNetBufferDataStart(FirstNetBuffer, 8u, 0, 0i64);
          }
          else
          {
            FirstNetBuffer->DataOffset += 8;
            FirstNetBuffer->DataLength -= 8;
            FirstNetBuffer->CurrentMdlOffset = v60;
          }
          v53 = WORD1(v72[2]);
          goto LABEL_57;
        }
LABEL_86:
        v47 = -1073741670;
        goto LABEL_60;
      }
    }
LABEL_94:
    v47 = -1073676266;
    goto LABEL_60;
  }
LABEL_57:
  v54 = DataLength - v48;
  LOBYTE(v72[2]) = v48;
  if ( v53 == 2048 )
  {
    v55 = VmsPktParseIPv4Packet(
            (_DWORD)FirstNetBuffer,
            v54,
            v68,
            (unsigned int)v72,
            (__int64)NdisGetDataBuffer,
            (__int64)VmsPktAdvanceNetBuffer,
            (__int64)VmsPktRetreatNetBuffer,
            (__int64)VmsPktPvtGetLengthNetBuffer,
            v53 - 2048 + 1);
LABEL_59:
    v47 = v55;
    goto LABEL_60;
  }
  if ( v53 == 34525 )
  {
    v55 = VmsPktParseIPv6Packet(
            (_DWORD)FirstNetBuffer,
            v54,
            v68,
            (unsigned int)v72,
            (__int64)NdisGetDataBuffer,
            (__int64)VmsPktAdvanceNetBuffer,
            (__int64)VmsPktRetreatNetBuffer,
            (__int64)VmsPktPvtGetLengthNetBuffer,
            1);
    goto LABEL_59;
  }
LABEL_60:
  LODWORD(v72[15]) -= v48;
  CurrentMdlOffset = FirstNetBuffer->CurrentMdlOffset;
  if ( CurrentMdlOffset < v48 )
  {
    NdisRetreatNetBufferDataStart(FirstNetBuffer, v48, 0, 0i64);
  }
  else
  {
    FirstNetBuffer->DataOffset -= v48;
    FirstNetBuffer->DataLength += v48;
    FirstNetBuffer->CurrentMdlOffset = CurrentMdlOffset - v48;
  }
  if ( v47 < 0 )
    goto LABEL_95;
  if ( WORD1(v72[2]) != 2048 )
  {
    if ( WORD1(v72[2]) == 0x86DD )
    {
      v63 = 1;
      goto LABEL_66;
    }
LABEL_95:
    NetBufferListContext = -1073676273;
    v23 = 0;
    goto LABEL_102;
  }
LABEL_66:
  LOWORD(v22) = LOBYTE(v72[10]);
  v21 = v64;
  v19 = LOBYTE(v72[10]) + 8;
LABEL_67:
  v62 = v19;
  NdisAdvanceNetBufferListDataStart(NetBufferList, (unsigned __int16)v19, 0, 0i64);
  v23 = 1;
LABEL_18:
  CloneNetBufferList = NdisAllocateCloneNetBufferList(NetBufferList, NetBufferListPoolHandle, NetBufferPoolHandle, 0);
  v20 = CloneNetBufferList;
  if ( !CloneNetBufferList )
  {
    NetBufferListContext = -1073741670;
    WPP_RECORDER_SF_qqqd(
      WPP_GLOBAL_Control->DeviceExtension,
      v25,
      12,
      11,
      (__int64)&WPP_5701215c40873077e73bea629dc5899a_Traceguids,
      (char)NetBufferList,
      (char)NetBufferListPoolHandle,
      (char)NetBufferPoolHandle,
      154);
    goto LABEL_102;
  }
  if ( v21 )
  {
    v40 = (unsigned __int16)v19;
    v41 = NdisRetreatNetBufferListDataStart(CloneNetBufferList, (unsigned __int16)v19, 0, 0i64, 0i64);
    NetBufferListContext = v41;
    if ( v41 < 0 )
    {
      WPP_RECORDER_SF_qDd(
        WPP_GLOBAL_Control->DeviceExtension,
        v42,
        12,
        12,
        (__int64)&WPP_5701215c40873077e73bea629dc5899a_Traceguids,
        (char)v20,
        v40,
        v41);
    }
    else
    {
      v65 = 1;
      NdisRetreatNetBufferListDataStart(NetBufferList, v40, 0, 0i64, 0i64);
      Alignment = NetBufferList->FirstNetBuffer;
      v44 = v20->FirstNetBuffer;
      v61[0] = 0;
      while ( 1 )
      {
        if ( !Alignment || !v44 )
        {
          VmsNblHelperIncrementSuccessCsoStats(NetBufferList, 0i64, 0i64, 0i64);
          v21 = v64;
          v23 = v61[0];
          goto LABEL_20;
        }
        NetBufferListContext = NdisCopyFromNetBufferToNetBuffer(
                                 v44,
                                 0,
                                 (unsigned __int16)v62,
                                 Alignment,
                                 0,
                                 &BytesCopied);
        if ( NetBufferListContext < 0 )
          break;
        if ( BytesCopied != (unsigned __int16)v62 && BytesCopied < Alignment->DataLength )
        {
          NetBufferListContext = -1073741670;
          break;
        }
        NetBufferListContext = SegLibDeferredChecksumPacket((unsigned int)v73, (_DWORD)v44, (_DWORD)v18, v45, v22, v63);
        if ( NetBufferListContext < 0 )
          break;
        Alignment = (_NET_BUFFER *)Alignment->Link.Alignment;
        v44 = (struct _NET_BUFFER *)v44->Link.Alignment;
      }
      v23 = v61[0];
    }
    goto LABEL_102;
  }
LABEL_20:
  NetBufferListContext = VmsNblHelperAllocateNetBufferListContext(v20, (int)FreeMdlHandler);
  if ( NetBufferListContext < 0 )
  {
LABEL_102:
    v28 = v62;
    goto LABEL_31;
  }
  v27 = v20->NetBufferListInfo[18];
  v28 = v62;
  v29 = v66;
  v27[1] = 0;
  *v27 = 1;
  v27[6] = 1;
  v27[8] = v28;
  if ( v29 )
    NdisCopyReceiveNetBufferListInfo(v20, NetBufferList);
  else
    NdisCopySendNetBufferListInfo(v20, NetBufferList);
  v31 = 0;
  if ( v21 )
  {
    v20->NetBufferListInfo[0] = 0i64;
    if ( !v29 )
      v20->NetBufferListInfo[2] = 0i64;
  }
  v20->ParentNetBufferList = NetBufferList;
  if ( !(_DWORD)FreeMdlHandler )
  {
    v9 = &NetBufferList->NetBufferListInfo[19];
    WORD1(v20->NetBufferListInfo[19]) = WORD1(NetBufferList->NetBufferListInfo[19]);
    BYTE4(v20->NetBufferListInfo[19]) = BYTE4(NetBufferList->NetBufferListInfo[19]);
    if ( NetBufferList == (PNET_BUFFER_LIST)-296i64 )
    {
      v30 = HIDWORD(v20->NetBufferListInfo[19]);
      LODWORD(v30) = v30 | 0x400;
      HIDWORD(v20->NetBufferListInfo[19]) = v30;
      LODWORD(v30) = v30 & 0xFEFFFFFF;
    }
    else
    {
      v32 = HIDWORD(v20->NetBufferListInfo[19]) ^ (HIDWORD(NetBufferList->NetBufferListInfo[19]) ^ HIDWORD(v20->NetBufferListInfo[19])) & 0x400;
      HIDWORD(v20->NetBufferListInfo[19]) = v32;
      v33 = (HIDWORD(NetBufferList->NetBufferListInfo[19]) ^ v32) & 0x7FF800 ^ v32;
      HIDWORD(v20->NetBufferListInfo[19]) = v33;
      v34 = (HIDWORD(NetBufferList->NetBufferListInfo[19]) ^ v33) & 0x800000 ^ v33;
      HIDWORD(v20->NetBufferListInfo[19]) = v34;
      v30 = v34 ^ (HIDWORD(NetBufferList->NetBufferListInfo[19]) ^ v34) & 0x1000000u;
    }
    HIDWORD(v20->NetBufferListInfo[19]) = v30;
    HIDWORD(v20->NetBufferListInfo[19]) = v30 ^ ((unsigned __int16)v30 ^ (unsigned __int16)HIDWORD(NetBufferList->NetBufferListInfo[19])) & 0x100;
  }
  if ( !a5 )
    VmsNblHelperRefCountIncrement(NetBufferList, v30, v9, 0i64);
  NetBufferListContext = v31;
  *v71 = v20;
LABEL_31:
  LOBYTE(v9) = 1;
  BLFlushBatchOpContextEx(v73, 0i64, v9);
  if ( NetBufferListContext < 0 )
  {
    if ( v23 )
      NdisRetreatNetBufferListDataStart(NetBufferList, v28, 0, 0i64, 0i64);
    if ( v20 )
    {
      if ( v65 )
        NdisAdvanceNetBufferListDataStart(v20, v28, 1u, 0i64);
      NdisFreeCloneNetBufferList(v20, 0);
    }
  }
  return (unsigned int)NetBufferListContext;
}