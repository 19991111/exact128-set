// Two power-of-two segments form one logical 147456-word main memory.
// Every command enables one segment. Both records share the full-word command.
module hw128_main_bank(
  input wire clk, read_enable, write_enable,
  input wire [17:0] address,
  input wire [127:0] write_data,
  output reg [127:0] read_data
);
  reg [127:0] lower [0:131071];
  reg [127:0] upper [0:16383];
  always @(posedge clk) begin
    if (read_enable) begin
      if (address[17]) read_data<=upper[address[13:0]];
      else read_data<=lower[address[16:0]];
    end
    if (write_enable) begin
      if (address[17]) upper[address[13:0]]<=write_data;
      else lower[address[16:0]]<=write_data;
    end
  end
endmodule

module hw128_aux_bank(
  input wire clk, read_enable, write_enable,
  input wire [13:0] address,
  input wire [511:0] write_data,
  output reg [511:0] read_data
);
  reg [511:0] words [0:16383];
  always @(posedge clk) begin
    if (read_enable) read_data<=words[address];
    if (write_enable) words[address]<=write_data;
  end
endmodule

module huawei128_memory(
  input wire clk, main_read, main_write,
  input wire [17:0] main_address,
  input wire [127:0] main_wdata,
  output wire [127:0] main_rdata,
  input wire aux_l_read, aux_r_read, aux_l_write, aux_r_write,
  input wire [13:0] aux_l_address, aux_r_address,
  input wire [511:0] aux_l_wdata, aux_r_wdata,
  output wire [511:0] aux_l_rdata, aux_r_rdata
);
  hw128_main_bank main_mem(clk, main_read, main_write, main_address, main_wdata, main_rdata);
  hw128_aux_bank left_aux(clk, aux_l_read, aux_l_write, aux_l_address, aux_l_wdata, aux_l_rdata);
  hw128_aux_bank right_aux(clk, aux_r_read, aux_r_write, aux_r_address, aux_r_wdata, aux_r_rdata);
endmodule
