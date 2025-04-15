//
// Created by Cheryl Chan on 21/02/2025.
//
//| 字段       | 长度（字节） | 说明                |
//|------------|--------------|---------------------|
//| Magic      | 2            | 固定值 0xDEAD       |
//| Version    | 1            | 协议版本（0x01）     |
//| PayloadLen | 2            | 后续数据的长度       |
//| Payload    | 变长         | 实际数据            |

#include <epan/packet.h>

// 定义协议字段
#define MYPROTO_MAGIC 0xDEAD

// 声明协议和字段标识符
static int ett_myproto;
static int proto_myproto;
static int hf_myproto_magic;
static int hf_myproto_version;
static int hf_myproto_payload_len;
static int hf_myproto_payload;
static dissector_handle_t myproto_handle;


// 协议字段的文本描述
static const value_string version_vals[] = {
    { 0x01, "Version 1.0" },
    { 0, NULL }
};

static int dissect_myproto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  g_message("MYPROTO dissector called!");
  proto_tree *myproto_tree;
  guint offset = 0;

  //显示协议名称
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "MYPROTO");
  col_clear(pinfo->cinfo, COL_INFO);

  //创建协议树节点
  proto_item *ti = proto_tree_add_item(tree, proto_myproto, tvb, 0, -1, ENC_NA);
  myproto_tree = proto_item_add_subtree(ti, ett_myproto);

  //Magic
  proto_tree_add_item(myproto_tree, hf_myproto_magic, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  //Version
  proto_tree_add_item(myproto_tree, hf_myproto_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  //Payload len
  guint payload_len = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(myproto_tree, hf_myproto_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  if (payload_len > 0) {
    proto_tree_add_item(myproto_tree, hf_myproto_payload, tvb, offset, payload_len, ENC_ASCII | ENC_NA);
      offset += payload_len;
  }
  return offset;
}

//注册协议和字段
void proto_register_myproto(void) {
  static hf_register_info hf[] = {
    { &hf_myproto_magic,
     { "Magic", "myproto.magic", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_myproto_version,
      { "Version", "myproto.version", FT_UINT8, BASE_HEX, VALS(version_vals), 0x0, NULL, HFILL }},
    { &hf_myproto_payload_len,
      {"Payload Length", "myproto.payload_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_myproto_payload,
     {"Payload", "myproto.payload", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };


  static int *ett[] = {
    &ett_myproto
  };

  proto_myproto = proto_register_protocol("My Custom Protocol", "MYPROTO", "myproto");

  proto_register_field_array(proto_myproto, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  myproto_handle = register_dissector("myproto", dissect_myproto, proto_myproto);
 }

void proto_reg_handoff_myproto(void) {
  //myproto_handle = register_dissector("myproto", dissect_myproto, proto_myproto);
 // myproto_handle = create_dissector_handle(dissect_myproto, proto_myproto);
  myproto_handle = find_dissector("myproto");
  dissector_add_uint("udp.port", 12345, myproto_handle); // 假设 MYPROTO 运行在 UDP 12345 端口
}
