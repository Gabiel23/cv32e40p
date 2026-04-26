module cv32e40p_aes_unit
  import cv32e40p_pkg::*;
(
    input  logic        clk_i,
    input  logic        rst_ni,

    input  logic        aes_en_i,
    input  aes_opcode_e aes_op_i,

    input  logic [ 1:0] aes_offset_i,
    input  logic        aes_result_sel_i,

    input  logic [31:0] aes_wdata_a_i,
    input  logic [31:0] aes_wdata_b_i,

    output logic [31:0] aes_rdata_a_o,
    output logic [31:0] aes_rdata_b_o,

    output logic        aes_ready_o,
    output logic        aes_busy_o
);

  typedef enum logic [3:0] {
    AES_IDLE,
    AES_E_INIT_ADDKEY,
    AES_E_SUBBYTES,
    AES_E_SHIFTROWS,
    AES_E_MIXCOLUMNS,
    AES_E_ADDROUNDKEY,
    AES_D_INIT_ADDKEY,
    AES_D_INVSHIFTROWS,
    AES_D_INVSUBBYTES,
    AES_D_ADDROUNDKEY,
    AES_D_INVMIXCOLUMNS,
    AES_DONE
  } aes_phase_e;

  logic [31:0] pt_regs  [0:3];
  logic [31:0] key_regs [0:3];
  logic [31:0] res_regs [0:3];

  logic [127:0] pt_block;
  logic [127:0] key_block;
  logic [127:0] state_reg;

  logic [127:0] round_keys [0:10];

  logic [127:0] init_addkey_enc_out;
  logic [127:0] subbytes_out;
  logic [127:0] shiftrows_out;
  logic [127:0] mixcolumns_out;
  logic [127:0] addroundkey_enc_out;

  logic [127:0] init_addkey_dec_out;
  logic [127:0] invshiftrows_out;
  logic [127:0] invsubbytes_out;
  logic [127:0] addroundkey_dec_out;
  logic [127:0] invmixcolumns_out;

  logic [3:0] round_cnt;
  aes_phase_e phase_reg;

  integer i;

  assign pt_block  = {pt_regs[0], pt_regs[1], pt_regs[2], pt_regs[3]};
  assign key_block = {key_regs[0], key_regs[1], key_regs[2], key_regs[3]};

  assign aes_busy_o  = (phase_reg != AES_IDLE);
  assign aes_ready_o = (phase_reg == AES_IDLE);

  assign round_keys[0] = key_block;

  genvar rk;
  generate
    for (rk = 1; rk <= 10; rk++) begin : gen_round_keys
      aes_key_expand_128 u_key_expand (
          .round_key_i (round_keys[rk-1]),
          .round_idx_i (rk[3:0]),
          .round_key_o (round_keys[rk])
      );
    end
  endgenerate

  aes_addroundkey u_init_addroundkey_enc (
      .state_i     (pt_block),
      .round_key_i (round_keys[0]),
      .state_o     (init_addkey_enc_out)
  );

  aes_subbytes u_subbytes (
      .state_i (state_reg),
      .state_o (subbytes_out)
  );

  aes_shiftrows u_shiftrows (
      .state_i (state_reg),
      .state_o (shiftrows_out)
  );

  aes_mixcolumns u_mixcolumns (
      .state_i (state_reg),
      .state_o (mixcolumns_out)
  );

  aes_addroundkey u_addroundkey_enc (
      .state_i     (state_reg),
      .round_key_i (round_keys[round_cnt]),
      .state_o     (addroundkey_enc_out)
  );

  aes_addroundkey u_init_addroundkey_dec (
      .state_i     (pt_block),
      .round_key_i (round_keys[10]),
      .state_o     (init_addkey_dec_out)
  );

  aes_invshiftrows u_invshiftrows (
      .state_i (state_reg),
      .state_o (invshiftrows_out)
  );

  aes_invsubbytes u_invsubbytes (
      .state_i (state_reg),
      .state_o (invsubbytes_out)
  );

  aes_addroundkey u_addroundkey_dec (
      .state_i     (state_reg),
      .round_key_i (round_keys[round_cnt]),
      .state_o     (addroundkey_dec_out)
  );

  aes_invmixcolumns u_invmixcolumns (
      .state_i (state_reg),
      .state_o (invmixcolumns_out)
  );

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      for (i = 0; i < 4; i++) begin
        pt_regs[i]  <= 32'b0;
        key_regs[i] <= 32'b0;
        res_regs[i] <= 32'b0;
      end

      state_reg <= 128'b0;
      round_cnt <= 4'd0;
      phase_reg <= AES_IDLE;
    end else begin
      unique case (phase_reg)

        AES_IDLE: begin
          if (aes_en_i) begin
            unique case (aes_op_i)

              AES_OP_STORE: begin
                unique case (aes_offset_i)
                  2'd0: begin
                    pt_regs[0] <= aes_wdata_a_i;
                    pt_regs[1] <= aes_wdata_b_i;
                  end

                  2'd1: begin
                    pt_regs[2] <= aes_wdata_a_i;
                    pt_regs[3] <= aes_wdata_b_i;
                  end

                  2'd2: begin
                    key_regs[0] <= aes_wdata_a_i;
                    key_regs[1] <= aes_wdata_b_i;
                  end

                  2'd3: begin
                    key_regs[2] <= aes_wdata_a_i;
                    key_regs[3] <= aes_wdata_b_i;
                  end

                  default: begin
                  end
                endcase
              end

              AES_OP_ENCRYPT: begin
                round_cnt <= 4'd1;
                phase_reg <= AES_E_INIT_ADDKEY;
              end

              AES_OP_DECRYPT: begin
                round_cnt <= 4'd9;
                phase_reg <= AES_D_INIT_ADDKEY;
              end

              default: begin
              end
            endcase
          end
        end

        AES_E_INIT_ADDKEY: begin
          state_reg <= init_addkey_enc_out;
          phase_reg <= AES_E_SUBBYTES;
        end

        AES_E_SUBBYTES: begin
          state_reg <= subbytes_out;
          phase_reg <= AES_E_SHIFTROWS;
        end

        AES_E_SHIFTROWS: begin
          state_reg <= shiftrows_out;
          if (round_cnt == 4'd10)
            phase_reg <= AES_E_ADDROUNDKEY;
          else
            phase_reg <= AES_E_MIXCOLUMNS;
        end

        AES_E_MIXCOLUMNS: begin
          state_reg <= mixcolumns_out;
          phase_reg <= AES_E_ADDROUNDKEY;
        end

        AES_E_ADDROUNDKEY: begin
          if (round_cnt == 4'd10) begin
            state_reg   <= addroundkey_enc_out;
            res_regs[0] <= addroundkey_enc_out[127:96];
            res_regs[1] <= addroundkey_enc_out[95:64];
            res_regs[2] <= addroundkey_enc_out[63:32];
            res_regs[3] <= addroundkey_enc_out[31:0];
            phase_reg   <= AES_DONE;
          end else begin
            state_reg <= addroundkey_enc_out;
            round_cnt <= round_cnt + 4'd1;
            phase_reg <= AES_E_SUBBYTES;
          end
        end

        AES_D_INIT_ADDKEY: begin
          state_reg <= init_addkey_dec_out;
          phase_reg <= AES_D_INVSHIFTROWS;
        end

        AES_D_INVSHIFTROWS: begin
          state_reg <= invshiftrows_out;
          phase_reg <= AES_D_INVSUBBYTES;
        end

        AES_D_INVSUBBYTES: begin
          state_reg <= invsubbytes_out;
          phase_reg <= AES_D_ADDROUNDKEY;
        end

        AES_D_ADDROUNDKEY: begin
          if (round_cnt == 4'd0) begin
            state_reg   <= addroundkey_dec_out;
            res_regs[0] <= addroundkey_dec_out[127:96];
            res_regs[1] <= addroundkey_dec_out[95:64];
            res_regs[2] <= addroundkey_dec_out[63:32];
            res_regs[3] <= addroundkey_dec_out[31:0];
            phase_reg   <= AES_DONE;
          end else begin
            state_reg <= addroundkey_dec_out;
            phase_reg <= AES_D_INVMIXCOLUMNS;
          end
        end

        AES_D_INVMIXCOLUMNS: begin
          state_reg <= invmixcolumns_out;
          round_cnt <= round_cnt - 4'd1;
          phase_reg <= AES_D_INVSHIFTROWS;
        end

        AES_DONE: begin
          round_cnt <= 4'd0;
          phase_reg <= AES_IDLE;
        end

        default: begin
          phase_reg <= AES_IDLE;
        end
      endcase
    end
  end

  always_comb begin
    aes_rdata_a_o = 32'b0;
    aes_rdata_b_o = 32'b0;

    if (aes_en_i && (aes_op_i == AES_OP_LOAD)) begin
      unique case (aes_result_sel_i)
        1'b0: begin
          aes_rdata_a_o = res_regs[0];
          aes_rdata_b_o = res_regs[1];
        end

        1'b1: begin
          aes_rdata_a_o = res_regs[2];
          aes_rdata_b_o = res_regs[3];
        end

        default: begin
          aes_rdata_a_o = 32'b0;
          aes_rdata_b_o = 32'b0;
        end
      endcase
    end
  end

endmodule


module aes_addroundkey (
    input  logic [127:0] state_i,
    input  logic [127:0] round_key_i,
    output logic [127:0] state_o
);

  assign state_o = state_i ^ round_key_i;

endmodule


module aes_subbytes (
    input  logic [127:0] state_i,
    output logic [127:0] state_o
);

  genvar i;
  generate
    for (i = 0; i < 16; i++) begin : gen_sbox
      aes_sbox_rom u_sbox (
          .addr_i (state_i[127 - i*8 -: 8]),
          .data_o (state_o[127 - i*8 -: 8])
      );
    end
  endgenerate

endmodule


module aes_invsubbytes (
    input  logic [127:0] state_i,
    output logic [127:0] state_o
);

  genvar i;
  generate
    for (i = 0; i < 16; i++) begin : gen_invsbox
      aes_invsbox_rom u_invsbox (
          .addr_i (state_i[127 - i*8 -: 8]),
          .data_o (state_o[127 - i*8 -: 8])
      );
    end
  endgenerate

endmodule


module aes_shiftrows (
    input  logic [127:0] state_i,
    output logic [127:0] state_o
);

  logic [7:0] b [0:15];

  always_comb begin
    b[0]  = state_i[127:120];
    b[1]  = state_i[119:112];
    b[2]  = state_i[111:104];
    b[3]  = state_i[103:96];
    b[4]  = state_i[95:88];
    b[5]  = state_i[87:80];
    b[6]  = state_i[79:72];
    b[7]  = state_i[71:64];
    b[8]  = state_i[63:56];
    b[9]  = state_i[55:48];
    b[10] = state_i[47:40];
    b[11] = state_i[39:32];
    b[12] = state_i[31:24];
    b[13] = state_i[23:16];
    b[14] = state_i[15:8];
    b[15] = state_i[7:0];

    state_o = {
      b[0],  b[5],  b[10], b[15],
      b[4],  b[9],  b[14], b[3],
      b[8],  b[13], b[2],  b[7],
      b[12], b[1],  b[6],  b[11]
    };
  end

endmodule


module aes_invshiftrows (
    input  logic [127:0] state_i,
    output logic [127:0] state_o
);

  logic [7:0] b [0:15];

  always_comb begin
    b[0]  = state_i[127:120];
    b[1]  = state_i[119:112];
    b[2]  = state_i[111:104];
    b[3]  = state_i[103:96];
    b[4]  = state_i[95:88];
    b[5]  = state_i[87:80];
    b[6]  = state_i[79:72];
    b[7]  = state_i[71:64];
    b[8]  = state_i[63:56];
    b[9]  = state_i[55:48];
    b[10] = state_i[47:40];
    b[11] = state_i[39:32];
    b[12] = state_i[31:24];
    b[13] = state_i[23:16];
    b[14] = state_i[15:8];
    b[15] = state_i[7:0];

    state_o = {
      b[0],  b[13], b[10], b[7],
      b[4],  b[1],  b[14], b[11],
      b[8],  b[5],  b[2],  b[15],
      b[12], b[9],  b[6],  b[3]
    };
  end

endmodule


module aes_mixcolumns (
    input  logic [127:0] state_i,
    output logic [127:0] state_o
);

  function automatic logic [7:0] xtime(input logic [7:0] x);
    begin
      xtime = {x[6:0], 1'b0} ^ (8'h1b & {8{x[7]}});
    end
  endfunction

  function automatic logic [7:0] gm2(input logic [7:0] x);
    begin
      gm2 = xtime(x);
    end
  endfunction

  function automatic logic [7:0] gm3(input logic [7:0] x);
    begin
      gm3 = xtime(x) ^ x;
    end
  endfunction

  function automatic logic [31:0] mixw(input logic [31:0] w);
    logic [7:0] b0, b1, b2, b3;
    logic [7:0] r0, r1, r2, r3;
    begin
      b0 = w[31:24];
      b1 = w[23:16];
      b2 = w[15:8];
      b3 = w[7:0];

      r0 = gm2(b0) ^ gm3(b1) ^ b2      ^ b3;
      r1 = b0      ^ gm2(b1) ^ gm3(b2) ^ b3;
      r2 = b0      ^ b1      ^ gm2(b2) ^ gm3(b3);
      r3 = gm3(b0) ^ b1      ^ b2      ^ gm2(b3);

      mixw = {r0, r1, r2, r3};
    end
  endfunction

  always_comb begin
    state_o = {
      mixw(state_i[127:96]),
      mixw(state_i[95:64]),
      mixw(state_i[63:32]),
      mixw(state_i[31:0])
    };
  end

endmodule


module aes_invmixcolumns (
    input  logic [127:0] state_i,
    output logic [127:0] state_o
);

  function automatic logic [7:0] xtime(input logic [7:0] x);
    begin
      xtime = {x[6:0], 1'b0} ^ (8'h1b & {8{x[7]}});
    end
  endfunction

  function automatic logic [7:0] gm2(input logic [7:0] x);
    begin
      gm2 = xtime(x);
    end
  endfunction

  function automatic logic [7:0] gm4(input logic [7:0] x);
    begin
      gm4 = gm2(gm2(x));
    end
  endfunction

  function automatic logic [7:0] gm8(input logic [7:0] x);
    begin
      gm8 = gm2(gm4(x));
    end
  endfunction

  function automatic logic [7:0] gm9(input logic [7:0] x);
    begin
      gm9 = gm8(x) ^ x;
    end
  endfunction

  function automatic logic [7:0] gm11(input logic [7:0] x);
    begin
      gm11 = gm8(x) ^ gm2(x) ^ x;
    end
  endfunction

  function automatic logic [7:0] gm13(input logic [7:0] x);
    begin
      gm13 = gm8(x) ^ gm4(x) ^ x;
    end
  endfunction

  function automatic logic [7:0] gm14(input logic [7:0] x);
    begin
      gm14 = gm8(x) ^ gm4(x) ^ gm2(x);
    end
  endfunction

  function automatic logic [31:0] invmixw(input logic [31:0] w);
    logic [7:0] b0, b1, b2, b3;
    logic [7:0] r0, r1, r2, r3;
    begin
      b0 = w[31:24];
      b1 = w[23:16];
      b2 = w[15:8];
      b3 = w[7:0];

      r0 = gm14(b0) ^ gm11(b1) ^ gm13(b2) ^ gm9(b3);
      r1 = gm9(b0)  ^ gm14(b1) ^ gm11(b2) ^ gm13(b3);
      r2 = gm13(b0) ^ gm9(b1)  ^ gm14(b2) ^ gm11(b3);
      r3 = gm11(b0) ^ gm13(b1) ^ gm9(b2)  ^ gm14(b3);

      invmixw = {r0, r1, r2, r3};
    end
  endfunction

  always_comb begin
    state_o = {
      invmixw(state_i[127:96]),
      invmixw(state_i[95:64]),
      invmixw(state_i[63:32]),
      invmixw(state_i[31:0])
    };
  end

endmodule


module aes_key_expand_128 (
    input  logic [127:0] round_key_i,
    input  logic [3:0]   round_idx_i,
    output logic [127:0] round_key_o
);

  logic [31:0] w0, w1, w2, w3;
  logic [31:0] rotw;
  logic [31:0] subw;
  logic [31:0] temp;

  logic [7:0] sb0, sb1, sb2, sb3;
  logic [7:0] rcon;

  logic [31:0] nw0, nw1, nw2, nw3;

  assign w0 = round_key_i[127:96];
  assign w1 = round_key_i[95:64];
  assign w2 = round_key_i[63:32];
  assign w3 = round_key_i[31:0];

  assign rotw = {w3[23:0], w3[31:24]};

  aes_sbox_rom u_sbox0 (.addr_i(rotw[31:24]), .data_o(sb0));
  aes_sbox_rom u_sbox1 (.addr_i(rotw[23:16]), .data_o(sb1));
  aes_sbox_rom u_sbox2 (.addr_i(rotw[15:8]),  .data_o(sb2));
  aes_sbox_rom u_sbox3 (.addr_i(rotw[7:0]),   .data_o(sb3));

  assign subw = {sb0, sb1, sb2, sb3};

  always_comb begin
    unique case (round_idx_i)
      4'd1:  rcon = 8'h01;
      4'd2:  rcon = 8'h02;
      4'd3:  rcon = 8'h04;
      4'd4:  rcon = 8'h08;
      4'd5:  rcon = 8'h10;
      4'd6:  rcon = 8'h20;
      4'd7:  rcon = 8'h40;
      4'd8:  rcon = 8'h80;
      4'd9:  rcon = 8'h1b;
      4'd10: rcon = 8'h36;
      default: rcon = 8'h00;
    endcase
  end

  assign temp = subw ^ {rcon, 24'h000000};

  assign nw0 = w0 ^ temp;
  assign nw1 = w1 ^ nw0;
  assign nw2 = w2 ^ nw1;
  assign nw3 = w3 ^ nw2;

  assign round_key_o = {nw0, nw1, nw2, nw3};

endmodule


module aes_sbox_rom (
    input  logic [7:0] addr_i,
    output logic [7:0] data_o
);

  always_comb begin
    unique case (addr_i)
      8'h00: data_o = 8'h63; 8'h01: data_o = 8'h7c; 8'h02: data_o = 8'h77; 8'h03: data_o = 8'h7b;
      8'h04: data_o = 8'hf2; 8'h05: data_o = 8'h6b; 8'h06: data_o = 8'h6f; 8'h07: data_o = 8'hc5;
      8'h08: data_o = 8'h30; 8'h09: data_o = 8'h01; 8'h0a: data_o = 8'h67; 8'h0b: data_o = 8'h2b;
      8'h0c: data_o = 8'hfe; 8'h0d: data_o = 8'hd7; 8'h0e: data_o = 8'hab; 8'h0f: data_o = 8'h76;
      8'h10: data_o = 8'hca; 8'h11: data_o = 8'h82; 8'h12: data_o = 8'hc9; 8'h13: data_o = 8'h7d;
      8'h14: data_o = 8'hfa; 8'h15: data_o = 8'h59; 8'h16: data_o = 8'h47; 8'h17: data_o = 8'hf0;
      8'h18: data_o = 8'had; 8'h19: data_o = 8'hd4; 8'h1a: data_o = 8'ha2; 8'h1b: data_o = 8'haf;
      8'h1c: data_o = 8'h9c; 8'h1d: data_o = 8'ha4; 8'h1e: data_o = 8'h72; 8'h1f: data_o = 8'hc0;
      8'h20: data_o = 8'hb7; 8'h21: data_o = 8'hfd; 8'h22: data_o = 8'h93; 8'h23: data_o = 8'h26;
      8'h24: data_o = 8'h36; 8'h25: data_o = 8'h3f; 8'h26: data_o = 8'hf7; 8'h27: data_o = 8'hcc;
      8'h28: data_o = 8'h34; 8'h29: data_o = 8'ha5; 8'h2a: data_o = 8'he5; 8'h2b: data_o = 8'hf1;
      8'h2c: data_o = 8'h71; 8'h2d: data_o = 8'hd8; 8'h2e: data_o = 8'h31; 8'h2f: data_o = 8'h15;
      8'h30: data_o = 8'h04; 8'h31: data_o = 8'hc7; 8'h32: data_o = 8'h23; 8'h33: data_o = 8'hc3;
      8'h34: data_o = 8'h18; 8'h35: data_o = 8'h96; 8'h36: data_o = 8'h05; 8'h37: data_o = 8'h9a;
      8'h38: data_o = 8'h07; 8'h39: data_o = 8'h12; 8'h3a: data_o = 8'h80; 8'h3b: data_o = 8'he2;
      8'h3c: data_o = 8'heb; 8'h3d: data_o = 8'h27; 8'h3e: data_o = 8'hb2; 8'h3f: data_o = 8'h75;
      8'h40: data_o = 8'h09; 8'h41: data_o = 8'h83; 8'h42: data_o = 8'h2c; 8'h43: data_o = 8'h1a;
      8'h44: data_o = 8'h1b; 8'h45: data_o = 8'h6e; 8'h46: data_o = 8'h5a; 8'h47: data_o = 8'ha0;
      8'h48: data_o = 8'h52; 8'h49: data_o = 8'h3b; 8'h4a: data_o = 8'hd6; 8'h4b: data_o = 8'hb3;
      8'h4c: data_o = 8'h29; 8'h4d: data_o = 8'he3; 8'h4e: data_o = 8'h2f; 8'h4f: data_o = 8'h84;
      8'h50: data_o = 8'h53; 8'h51: data_o = 8'hd1; 8'h52: data_o = 8'h00; 8'h53: data_o = 8'hed;
      8'h54: data_o = 8'h20; 8'h55: data_o = 8'hfc; 8'h56: data_o = 8'hb1; 8'h57: data_o = 8'h5b;
      8'h58: data_o = 8'h6a; 8'h59: data_o = 8'hcb; 8'h5a: data_o = 8'hbe; 8'h5b: data_o = 8'h39;
      8'h5c: data_o = 8'h4a; 8'h5d: data_o = 8'h4c; 8'h5e: data_o = 8'h58; 8'h5f: data_o = 8'hcf;
      8'h60: data_o = 8'hd0; 8'h61: data_o = 8'hef; 8'h62: data_o = 8'haa; 8'h63: data_o = 8'hfb;
      8'h64: data_o = 8'h43; 8'h65: data_o = 8'h4d; 8'h66: data_o = 8'h33; 8'h67: data_o = 8'h85;
      8'h68: data_o = 8'h45; 8'h69: data_o = 8'hf9; 8'h6a: data_o = 8'h02; 8'h6b: data_o = 8'h7f;
      8'h6c: data_o = 8'h50; 8'h6d: data_o = 8'h3c; 8'h6e: data_o = 8'h9f; 8'h6f: data_o = 8'ha8;
      8'h70: data_o = 8'h51; 8'h71: data_o = 8'ha3; 8'h72: data_o = 8'h40; 8'h73: data_o = 8'h8f;
      8'h74: data_o = 8'h92; 8'h75: data_o = 8'h9d; 8'h76: data_o = 8'h38; 8'h77: data_o = 8'hf5;
      8'h78: data_o = 8'hbc; 8'h79: data_o = 8'hb6; 8'h7a: data_o = 8'hda; 8'h7b: data_o = 8'h21;
      8'h7c: data_o = 8'h10; 8'h7d: data_o = 8'hff; 8'h7e: data_o = 8'hf3; 8'h7f: data_o = 8'hd2;
      8'h80: data_o = 8'hcd; 8'h81: data_o = 8'h0c; 8'h82: data_o = 8'h13; 8'h83: data_o = 8'hec;
      8'h84: data_o = 8'h5f; 8'h85: data_o = 8'h97; 8'h86: data_o = 8'h44; 8'h87: data_o = 8'h17;
      8'h88: data_o = 8'hc4; 8'h89: data_o = 8'ha7; 8'h8a: data_o = 8'h7e; 8'h8b: data_o = 8'h3d;
      8'h8c: data_o = 8'h64; 8'h8d: data_o = 8'h5d; 8'h8e: data_o = 8'h19; 8'h8f: data_o = 8'h73;
      8'h90: data_o = 8'h60; 8'h91: data_o = 8'h81; 8'h92: data_o = 8'h4f; 8'h93: data_o = 8'hdc;
      8'h94: data_o = 8'h22; 8'h95: data_o = 8'h2a; 8'h96: data_o = 8'h90; 8'h97: data_o = 8'h88;
      8'h98: data_o = 8'h46; 8'h99: data_o = 8'hee; 8'h9a: data_o = 8'hb8; 8'h9b: data_o = 8'h14;
      8'h9c: data_o = 8'hde; 8'h9d: data_o = 8'h5e; 8'h9e: data_o = 8'h0b; 8'h9f: data_o = 8'hdb;
      8'ha0: data_o = 8'he0; 8'ha1: data_o = 8'h32; 8'ha2: data_o = 8'h3a; 8'ha3: data_o = 8'h0a;
      8'ha4: data_o = 8'h49; 8'ha5: data_o = 8'h06; 8'ha6: data_o = 8'h24; 8'ha7: data_o = 8'h5c;
      8'ha8: data_o = 8'hc2; 8'ha9: data_o = 8'hd3; 8'haa: data_o = 8'hac; 8'hab: data_o = 8'h62;
      8'hac: data_o = 8'h91; 8'had: data_o = 8'h95; 8'hae: data_o = 8'he4; 8'haf: data_o = 8'h79;
      8'hb0: data_o = 8'he7; 8'hb1: data_o = 8'hc8; 8'hb2: data_o = 8'h37; 8'hb3: data_o = 8'h6d;
      8'hb4: data_o = 8'h8d; 8'hb5: data_o = 8'hd5; 8'hb6: data_o = 8'h4e; 8'hb7: data_o = 8'ha9;
      8'hb8: data_o = 8'h6c; 8'hb9: data_o = 8'h56; 8'hba: data_o = 8'hf4; 8'hbb: data_o = 8'hea;
      8'hbc: data_o = 8'h65; 8'hbd: data_o = 8'h7a; 8'hbe: data_o = 8'hae; 8'hbf: data_o = 8'h08;
      8'hc0: data_o = 8'hba; 8'hc1: data_o = 8'h78; 8'hc2: data_o = 8'h25; 8'hc3: data_o = 8'h2e;
      8'hc4: data_o = 8'h1c; 8'hc5: data_o = 8'ha6; 8'hc6: data_o = 8'hb4; 8'hc7: data_o = 8'hc6;
      8'hc8: data_o = 8'he8; 8'hc9: data_o = 8'hdd; 8'hca: data_o = 8'h74; 8'hcb: data_o = 8'h1f;
      8'hcc: data_o = 8'h4b; 8'hcd: data_o = 8'hbd; 8'hce: data_o = 8'h8b; 8'hcf: data_o = 8'h8a;
      8'hd0: data_o = 8'h70; 8'hd1: data_o = 8'h3e; 8'hd2: data_o = 8'hb5; 8'hd3: data_o = 8'h66;
      8'hd4: data_o = 8'h48; 8'hd5: data_o = 8'h03; 8'hd6: data_o = 8'hf6; 8'hd7: data_o = 8'h0e;
      8'hd8: data_o = 8'h61; 8'hd9: data_o = 8'h35; 8'hda: data_o = 8'h57; 8'hdb: data_o = 8'hb9;
      8'hdc: data_o = 8'h86; 8'hdd: data_o = 8'hc1; 8'hde: data_o = 8'h1d; 8'hdf: data_o = 8'h9e;
      8'he0: data_o = 8'he1; 8'he1: data_o = 8'hf8; 8'he2: data_o = 8'h98; 8'he3: data_o = 8'h11;
      8'he4: data_o = 8'h69; 8'he5: data_o = 8'hd9; 8'he6: data_o = 8'h8e; 8'he7: data_o = 8'h94;
      8'he8: data_o = 8'h9b; 8'he9: data_o = 8'h1e; 8'hea: data_o = 8'h87; 8'heb: data_o = 8'he9;
      8'hec: data_o = 8'hce; 8'hed: data_o = 8'h55; 8'hee: data_o = 8'h28; 8'hef: data_o = 8'hdf;
      8'hf0: data_o = 8'h8c; 8'hf1: data_o = 8'ha1; 8'hf2: data_o = 8'h89; 8'hf3: data_o = 8'h0d;
      8'hf4: data_o = 8'hbf; 8'hf5: data_o = 8'he6; 8'hf6: data_o = 8'h42; 8'hf7: data_o = 8'h68;
      8'hf8: data_o = 8'h41; 8'hf9: data_o = 8'h99; 8'hfa: data_o = 8'h2d; 8'hfb: data_o = 8'h0f;
      8'hfc: data_o = 8'hb0; 8'hfd: data_o = 8'h54; 8'hfe: data_o = 8'hbb; 8'hff: data_o = 8'h16;
    endcase
  end

endmodule


module aes_invsbox_rom (
    input  logic [7:0] addr_i,
    output logic [7:0] data_o
);

  always_comb begin
    unique case (addr_i)
      8'h00: data_o = 8'h52; 8'h01: data_o = 8'h09; 8'h02: data_o = 8'h6a; 8'h03: data_o = 8'hd5;
      8'h04: data_o = 8'h30; 8'h05: data_o = 8'h36; 8'h06: data_o = 8'ha5; 8'h07: data_o = 8'h38;
      8'h08: data_o = 8'hbf; 8'h09: data_o = 8'h40; 8'h0a: data_o = 8'ha3; 8'h0b: data_o = 8'h9e;
      8'h0c: data_o = 8'h81; 8'h0d: data_o = 8'hf3; 8'h0e: data_o = 8'hd7; 8'h0f: data_o = 8'hfb;
      8'h10: data_o = 8'h7c; 8'h11: data_o = 8'he3; 8'h12: data_o = 8'h39; 8'h13: data_o = 8'h82;
      8'h14: data_o = 8'h9b; 8'h15: data_o = 8'h2f; 8'h16: data_o = 8'hff; 8'h17: data_o = 8'h87;
      8'h18: data_o = 8'h34; 8'h19: data_o = 8'h8e; 8'h1a: data_o = 8'h43; 8'h1b: data_o = 8'h44;
      8'h1c: data_o = 8'hc4; 8'h1d: data_o = 8'hde; 8'h1e: data_o = 8'he9; 8'h1f: data_o = 8'hcb;
      8'h20: data_o = 8'h54; 8'h21: data_o = 8'h7b; 8'h22: data_o = 8'h94; 8'h23: data_o = 8'h32;
      8'h24: data_o = 8'ha6; 8'h25: data_o = 8'hc2; 8'h26: data_o = 8'h23; 8'h27: data_o = 8'h3d;
      8'h28: data_o = 8'hee; 8'h29: data_o = 8'h4c; 8'h2a: data_o = 8'h95; 8'h2b: data_o = 8'h0b;
      8'h2c: data_o = 8'h42; 8'h2d: data_o = 8'hfa; 8'h2e: data_o = 8'hc3; 8'h2f: data_o = 8'h4e;
      8'h30: data_o = 8'h08; 8'h31: data_o = 8'h2e; 8'h32: data_o = 8'ha1; 8'h33: data_o = 8'h66;
      8'h34: data_o = 8'h28; 8'h35: data_o = 8'hd9; 8'h36: data_o = 8'h24; 8'h37: data_o = 8'hb2;
      8'h38: data_o = 8'h76; 8'h39: data_o = 8'h5b; 8'h3a: data_o = 8'ha2; 8'h3b: data_o = 8'h49;
      8'h3c: data_o = 8'h6d; 8'h3d: data_o = 8'h8b; 8'h3e: data_o = 8'hd1; 8'h3f: data_o = 8'h25;
      8'h40: data_o = 8'h72; 8'h41: data_o = 8'hf8; 8'h42: data_o = 8'hf6; 8'h43: data_o = 8'h64;
      8'h44: data_o = 8'h86; 8'h45: data_o = 8'h68; 8'h46: data_o = 8'h98; 8'h47: data_o = 8'h16;
      8'h48: data_o = 8'hd4; 8'h49: data_o = 8'ha4; 8'h4a: data_o = 8'h5c; 8'h4b: data_o = 8'hcc;
      8'h4c: data_o = 8'h5d; 8'h4d: data_o = 8'h65; 8'h4e: data_o = 8'hb6; 8'h4f: data_o = 8'h92;
      8'h50: data_o = 8'h6c; 8'h51: data_o = 8'h70; 8'h52: data_o = 8'h48; 8'h53: data_o = 8'h50;
      8'h54: data_o = 8'hfd; 8'h55: data_o = 8'hed; 8'h56: data_o = 8'hb9; 8'h57: data_o = 8'hda;
      8'h58: data_o = 8'h5e; 8'h59: data_o = 8'h15; 8'h5a: data_o = 8'h46; 8'h5b: data_o = 8'h57;
      8'h5c: data_o = 8'ha7; 8'h5d: data_o = 8'h8d; 8'h5e: data_o = 8'h9d; 8'h5f: data_o = 8'h84;
      8'h60: data_o = 8'h90; 8'h61: data_o = 8'hd8; 8'h62: data_o = 8'hab; 8'h63: data_o = 8'h00;
      8'h64: data_o = 8'h8c; 8'h65: data_o = 8'hbc; 8'h66: data_o = 8'hd3; 8'h67: data_o = 8'h0a;
      8'h68: data_o = 8'hf7; 8'h69: data_o = 8'he4; 8'h6a: data_o = 8'h58; 8'h6b: data_o = 8'h05;
      8'h6c: data_o = 8'hb8; 8'h6d: data_o = 8'hb3; 8'h6e: data_o = 8'h45; 8'h6f: data_o = 8'h06;
      8'h70: data_o = 8'hd0; 8'h71: data_o = 8'h2c; 8'h72: data_o = 8'h1e; 8'h73: data_o = 8'h8f;
      8'h74: data_o = 8'hca; 8'h75: data_o = 8'h3f; 8'h76: data_o = 8'h0f; 8'h77: data_o = 8'h02;
      8'h78: data_o = 8'hc1; 8'h79: data_o = 8'haf; 8'h7a: data_o = 8'hbd; 8'h7b: data_o = 8'h03;
      8'h7c: data_o = 8'h01; 8'h7d: data_o = 8'h13; 8'h7e: data_o = 8'h8a; 8'h7f: data_o = 8'h6b;
      8'h80: data_o = 8'h3a; 8'h81: data_o = 8'h91; 8'h82: data_o = 8'h11; 8'h83: data_o = 8'h41;
      8'h84: data_o = 8'h4f; 8'h85: data_o = 8'h67; 8'h86: data_o = 8'hdc; 8'h87: data_o = 8'hea;
      8'h88: data_o = 8'h97; 8'h89: data_o = 8'hf2; 8'h8a: data_o = 8'hcf; 8'h8b: data_o = 8'hce;
      8'h8c: data_o = 8'hf0; 8'h8d: data_o = 8'hb4; 8'h8e: data_o = 8'he6; 8'h8f: data_o = 8'h73;
      8'h90: data_o = 8'h96; 8'h91: data_o = 8'hac; 8'h92: data_o = 8'h74; 8'h93: data_o = 8'h22;
      8'h94: data_o = 8'he7; 8'h95: data_o = 8'had; 8'h96: data_o = 8'h35; 8'h97: data_o = 8'h85;
      8'h98: data_o = 8'he2; 8'h99: data_o = 8'hf9; 8'h9a: data_o = 8'h37; 8'h9b: data_o = 8'he8;
      8'h9c: data_o = 8'h1c; 8'h9d: data_o = 8'h75; 8'h9e: data_o = 8'hdf; 8'h9f: data_o = 8'h6e;
      8'ha0: data_o = 8'h47; 8'ha1: data_o = 8'hf1; 8'ha2: data_o = 8'h1a; 8'ha3: data_o = 8'h71;
      8'ha4: data_o = 8'h1d; 8'ha5: data_o = 8'h29; 8'ha6: data_o = 8'hc5; 8'ha7: data_o = 8'h89;
      8'ha8: data_o = 8'h6f; 8'ha9: data_o = 8'hb7; 8'haa: data_o = 8'h62; 8'hab: data_o = 8'h0e;
      8'hac: data_o = 8'haa; 8'had: data_o = 8'h18; 8'hae: data_o = 8'hbe; 8'haf: data_o = 8'h1b;
      8'hb0: data_o = 8'hfc; 8'hb1: data_o = 8'h56; 8'hb2: data_o = 8'h3e; 8'hb3: data_o = 8'h4b;
      8'hb4: data_o = 8'hc6; 8'hb5: data_o = 8'hd2; 8'hb6: data_o = 8'h79; 8'hb7: data_o = 8'h20;
      8'hb8: data_o = 8'h9a; 8'hb9: data_o = 8'hdb; 8'hba: data_o = 8'hc0; 8'hbb: data_o = 8'hfe;
      8'hbc: data_o = 8'h78; 8'hbd: data_o = 8'hcd; 8'hbe: data_o = 8'h5a; 8'hbf: data_o = 8'hf4;
      8'hc0: data_o = 8'h1f; 8'hc1: data_o = 8'hdd; 8'hc2: data_o = 8'ha8; 8'hc3: data_o = 8'h33;
      8'hc4: data_o = 8'h88; 8'hc5: data_o = 8'h07; 8'hc6: data_o = 8'hc7; 8'hc7: data_o = 8'h31;
      8'hc8: data_o = 8'hb1; 8'hc9: data_o = 8'h12; 8'hca: data_o = 8'h10; 8'hcb: data_o = 8'h59;
      8'hcc: data_o = 8'h27; 8'hcd: data_o = 8'h80; 8'hce: data_o = 8'hec; 8'hcf: data_o = 8'h5f;
      8'hd0: data_o = 8'h60; 8'hd1: data_o = 8'h51; 8'hd2: data_o = 8'h7f; 8'hd3: data_o = 8'ha9;
      8'hd4: data_o = 8'h19; 8'hd5: data_o = 8'hb5; 8'hd6: data_o = 8'h4a; 8'hd7: data_o = 8'h0d;
      8'hd8: data_o = 8'h2d; 8'hd9: data_o = 8'he5; 8'hda: data_o = 8'h7a; 8'hdb: data_o = 8'h9f;
      8'hdc: data_o = 8'h93; 8'hdd: data_o = 8'hc9; 8'hde: data_o = 8'h9c; 8'hdf: data_o = 8'hef;
      8'he0: data_o = 8'ha0; 8'he1: data_o = 8'he0; 8'he2: data_o = 8'h3b; 8'he3: data_o = 8'h4d;
      8'he4: data_o = 8'hae; 8'he5: data_o = 8'h2a; 8'he6: data_o = 8'hf5; 8'he7: data_o = 8'hb0;
      8'he8: data_o = 8'hc8; 8'he9: data_o = 8'heb; 8'hea: data_o = 8'hbb; 8'heb: data_o = 8'h3c;
      8'hec: data_o = 8'h83; 8'hed: data_o = 8'h53; 8'hee: data_o = 8'h99; 8'hef: data_o = 8'h61;
      8'hf0: data_o = 8'h17; 8'hf1: data_o = 8'h2b; 8'hf2: data_o = 8'h04; 8'hf3: data_o = 8'h7e;
      8'hf4: data_o = 8'hba; 8'hf5: data_o = 8'h77; 8'hf6: data_o = 8'hd6; 8'hf7: data_o = 8'h26;
      8'hf8: data_o = 8'he1; 8'hf9: data_o = 8'h69; 8'hfa: data_o = 8'h14; 8'hfb: data_o = 8'h63;
      8'hfc: data_o = 8'h55; 8'hfd: data_o = 8'h21; 8'hfe: data_o = 8'h0c; 8'hff: data_o = 8'h7d;
    endcase
  end

endmodule
