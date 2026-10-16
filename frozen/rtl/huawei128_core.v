// Serialized controller. Read responses arrive one clock after a command.
// Generic hardware description; physical frequency and memory mapping are open.
module huawei128_core(
  input wire clk, reset, cmd_valid, cmd_insert,
  input wire [127:0] cmd_key,
  output wire cmd_ready, rsp_valid,
  input wire rsp_ready,
  output reg [3:0] rsp_status,
  output reg main_read, main_write,
  output reg [17:0] main_address,
  output wire [127:0] main_wdata,
  input wire [127:0] main_rdata,
  output reg aux_l_read, aux_r_read, aux_l_write, aux_r_write,
  output reg [13:0] aux_l_address, aux_r_address,
  output reg [511:0] aux_l_wdata, aux_r_wdata,
  input wire [511:0] aux_l_rdata, aux_r_rdata,
  output wire cam_search, cam_write,
  output reg [9:0] overflow_count,
  output reg [31:0] rejected_count,
  output wire [31:0] conflict_count
);
  localparam INIT=4'd0, IDLE=4'd1, CAM=4'd2, AUX=4'd3,
             CAPTURE_AUX=4'd4, DECIDE=4'd5, CAPTURE_MAIN=4'd6,
             COMPARE_MAIN=4'd7, COMMIT_MAIN=4'd8, OVERFLOW=4'd9,
             RESPONSE=4'd10;
  reg [3:0] phase;
  reg [13:0] init_row;
  reg insert_operation;
  reg [127:0] key_reg;
  reg [511:0] left_word, right_word;
  reg [127:0] main_word;
  reg [18:0] target_record;
  reg fresh;
  reg [1:0] overflow_reason;
  reg [127:0] overflow_keys [0:511];

  wire [127:0] value;
  wire [13:0] left = value[13:0];
  wire [49:0] fingerprint = value[63:14];
  wire [63:0] quotient = value[127:64];
  wire [13:0] right;
  hw128_hash_terminal hash_terminal(key_reg, value);
  hw128_hash_right hash_right(key_reg, right);
  assign cmd_ready = (phase == IDLE) & ~reset;
  assign rsp_valid = (phase == RESPONSE) & ~reset;
  assign cam_search = (phase == CAM) & ~reset;
  assign cam_write = (phase == OVERFLOW) & (overflow_count < 10'd512) & ~reset;
  assign conflict_count = rejected_count + {22'b0, overflow_count};

  wire [511:0] cam_hits;
  wire cam_hit = |cam_hits;
  genvar index;
  generate for (index=0; index<512; index=index+1) begin: cam_rows
    wire [127:0] difference = key_reg ^ overflow_keys[index];
    wire [127:0] negative = 128'd0 - difference;
    wire equality = (difference | negative) >> 127 ^ 1'b1;
    wire [10:0] valid_difference = {1'b0, overflow_count} - (index+1);
    wire valid = valid_difference[10] ^ 1'b1;
    assign cam_hits[index] = equality & valid;
  end endgenerate

  wire [3:0] left_slot, right_slot;
  wire left_present, right_present, left_multiple, right_multiple;
  hw128_match match_left(left_word, fingerprint, left_slot, left_present, left_multiple);
  hw128_match match_right(right_word, fingerprint, right_slot, right_present, right_multiple);
  wire [3:0] left_count = left_word[453:450];
  wire [3:0] right_count = right_word[453:450];
  wire choose_left = left_count <= right_count;
  wire [18:0] matched_record = left_present ?
      (19'd9 * {5'b0,left} + {15'b0,left_slot}) :
      (19'd147456 + 19'd9 * {5'b0,right} + {15'b0,right_slot});
  wire [18:0] free_record = choose_left ?
      (19'd9 * {5'b0,left} + {15'b0,left_count}) :
      (19'd147456 + 19'd9 * {5'b0,right} + {15'b0,right_count});
  wire [511:0] updated_left, updated_right;
  hw128_append append_left(left_word, left_count, fingerprint, updated_left);
  hw128_append append_right(right_word, right_count, fingerprint, updated_right);
  wire [63:0] selected_record = target_record[0] ? main_word[127:64] : main_word[63:0];
  wire equal;
  hw128_compare compare(selected_record, fingerprint, left, value, equal);
  // Preserve the other half, including a record in an adjacent odd-sized bucket.
  hw128_main_update update_main(main_word, quotient, target_record[0], main_wdata);

  always @* begin
    main_read=0; main_write=0; main_address=target_record[18:1];
    aux_l_read=0; aux_r_read=0; aux_l_write=0; aux_r_write=0;
    aux_l_address=left; aux_r_address=right;
    aux_l_wdata=updated_left; aux_r_wdata=updated_right;
    if (!reset) begin
      case (phase)
        INIT: begin
          aux_l_address=init_row; aux_r_address=init_row;
          aux_l_write=1; aux_r_write=1;
          aux_l_wdata=0; aux_r_wdata=0;
        end
        AUX: begin aux_l_read=1; aux_r_read=1; end
        DECIDE: begin
          if (left_present | right_present) begin
            main_read=1; main_address=matched_record[18:1];
          end else if (insert_operation &&
                       !((left_count == 4'd9) && (right_count == 4'd9))) begin
            main_read=1; main_address=free_record[18:1];
          end
        end
        COMMIT_MAIN: begin
          main_write=1;
          if (choose_left) aux_l_write=1;
          else aux_r_write=1;
        end
      endcase
    end
  end

  always @(posedge clk) begin
    if (reset) begin
      phase<=INIT; init_row<=0; key_reg<=0; insert_operation<=0;
      left_word<=0; right_word<=0; main_word<=0; target_record<=0;
      fresh<=0; overflow_reason<=0; rsp_status<=0;
      overflow_count<=0; rejected_count<=0;
    end else begin
      case (phase)
        INIT: begin
          if (init_row == 14'd16383) phase<=IDLE;
          else init_row<=init_row+14'd1;
        end
        IDLE: if (cmd_valid) begin
          key_reg<=cmd_key; insert_operation<=cmd_insert; phase<=CAM;
        end
        CAM: begin
          if (cam_hit) begin
            rsp_status<=insert_operation ? 4'd3 : 4'd1; phase<=RESPONSE;
          end else if (fingerprint == 50'd0) begin
            if (insert_operation) begin overflow_reason<=0; phase<=OVERFLOW; end
            else begin rsp_status<=0; phase<=RESPONSE; end
          end else phase<=AUX;
        end
        AUX: phase<=CAPTURE_AUX;
        CAPTURE_AUX: begin
          left_word<=aux_l_rdata; right_word<=aux_r_rdata; phase<=DECIDE;
        end
        DECIDE: begin
          if (left_present | right_present) begin
            target_record<=matched_record; fresh<=0; phase<=CAPTURE_MAIN;
          end else if (!insert_operation) begin rsp_status<=0; phase<=RESPONSE; end
          else if ((left_count == 4'd9) && (right_count == 4'd9)) begin
            overflow_reason<=2; phase<=OVERFLOW;
          end else begin target_record<=free_record; fresh<=1; phase<=CAPTURE_MAIN; end
        end
        CAPTURE_MAIN: begin main_word<=main_rdata; phase<=COMPARE_MAIN; end
        COMPARE_MAIN: begin
          if (fresh) phase<=COMMIT_MAIN;
          else if (!insert_operation) begin rsp_status<=equal ? 4'd1 : 4'd0; phase<=RESPONSE; end
          else if (equal) begin rsp_status<=3; phase<=RESPONSE; end
          else begin overflow_reason<=1; phase<=OVERFLOW; end
        end
        COMMIT_MAIN: begin rsp_status<=2; phase<=RESPONSE; end
        OVERFLOW: begin
          if (overflow_count < 10'd512) begin
            overflow_keys[overflow_count[8:0]]<=key_reg;
            overflow_count<=overflow_count+10'd1;
            rsp_status<=4'd4+{2'b0,overflow_reason};
          end else begin
            rejected_count<=rejected_count+32'd1;
            rsp_status<=4'd7+{2'b0,overflow_reason};
          end
          phase<=RESPONSE;
        end
        RESPONSE: if (rsp_ready) phase<=IDLE;
        default: phase<=INIT;
      endcase
    end
  end
endmodule

module hw128_main_update(input wire [127:0] old_word, input wire [63:0] record,
                         input wire half, output wire [127:0] updated);
  assign updated = half ? {record,old_word[63:0]} : {old_word[127:64],record};
endmodule

module hw128_compare(input wire [63:0] record, input wire [49:0] fingerprint,
                     input wire [13:0] left, input wire [127:0] value,
                     output wire equal);
  assign equal = {record,fingerprint,left} == value;
endmodule

module hw128_match(input wire [511:0] word, input wire [49:0] fingerprint,
                    output reg [3:0] slot, output wire present, multiple);
  wire [8:0] hits;
  genvar i;
  generate for (i=0; i<9; i=i+1) begin: slots
    assign hits[i] = word[50*i+:50] == fingerprint;
  end endgenerate
  assign present = |hits;
  assign multiple = |(hits & (hits - 9'd1));
  integer j;
  always @* begin
    slot=0;
    for (j=0; j<9; j=j+1) slot=slot | (hits[j] ? j[3:0] : 4'd0);
  end
endmodule

module hw128_append(input wire [511:0] word, input wire [3:0] count,
                    input wire [49:0] fingerprint, output wire [511:0] updated);
  wire [449:0] tags = word[449:0] | ({{400{1'b0}},fingerprint} << (count*10'd50));
  wire [3:0] next_count = count + 4'd1;
  assign updated = {58'b0,next_count,tags};
endmodule
