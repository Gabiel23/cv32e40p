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
    output logic [31:0] aes_rdata_b_o
);

  logic [31:0] pt_regs  [0:3];
  logic [31:0] key_regs [0:3];
  logic [31:0] res_regs [0:3];

  integer i;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      for (i = 0; i < 4; i++) begin
        pt_regs[i]  <= 32'b0;
        key_regs[i] <= 32'b0;
        res_regs[i] <= 32'b0;
      end
    end else begin
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
            
          end

          AES_OP_DECRYPT: begin
            
          end

          default: begin
          end
        endcase
      end
    end
  end

  always_comb begin
    aes_rdata_a_o = 32'b0;
    aes_rdata_b_o = 32'b0;

    if (aes_en_i && (aes_op_i == AES_OP_LOAD)) begin
      unique case (aes_result_sel_i)
        1'b0: begin
          aes_rdata_a_o = 32'hDEADBEEF;
          aes_rdata_b_o = 32'HCAFEBABE;
        end

        1'b1: begin
          aes_rdata_a_o = 32'hBEBEBEBE;
          aes_rdata_b_o = 32'hFEDEFEDE;
        end

        default: begin
          aes_rdata_a_o = 32'b0;
          aes_rdata_b_o = 32'b0;
        end
      endcase
    end
  end

endmodule
