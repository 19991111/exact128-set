// Universal bit-vector checks of the actual instantiated datapath modules.
module prove_main_update(input wire [127:0] old_word, input wire [63:0] record,
                         input wire half, output wire ok);
  wire [127:0] updated;
  hw128_main_update dut(old_word,record,half,updated);
  wire [127:0] lane_mask=128'hffffffffffffffff << {half,6'b0};
  wire [63:0] selected=updated >> {half,6'b0};
  assign ok=(selected==record) && ((updated & ~lane_mask)==(old_word & ~lane_mask));
endmodule

module prove_compare(input wire [63:0] record, input wire [49:0] fingerprint,
                     input wire [13:0] left, input wire [127:0] value, output wire ok);
  wire equal;
  hw128_compare dut(record,fingerprint,left,value,equal);
  assign ok=equal == ((record==value[127:64]) &&
                     (fingerprint==value[63:14]) && (left==value[13:0]));
endmodule

module prove_append(input wire [511:0] word, input wire [3:0] count,
                    input wire [49:0] fingerprint, output wire ok);
  wire [511:0] updated;
  hw128_append dut(word,count,fingerprint,updated);
  wire [9:0] shift=count*10'd50;
  wire [49:0] selected_old=word >> shift;
  wire [49:0] selected_new=updated >> shift;
  wire [449:0] lane_mask={{400{1'b0}},50'h3ffffffffffff} << shift;
  wire [449:0] unchanged=~lane_mask;
  assign ok=(count>8 || selected_old!=0) ||
            ((selected_new==fingerprint) && (updated[453:450]==count+4'd1) &&
             (updated[511:454]==0) &&
             ((word[449:0] & unchanged)==(updated[449:0] & unchanged)));
endmodule

module prove_match(input wire [511:0] word, input wire [49:0] fingerprint,
                   output wire ok);
  wire [3:0] slot;
  wire present,multiple;
  hw128_match dut(word,fingerprint,slot,present,multiple);
  wire [49:0] selected=word >> (slot*10'd50);
  wire [3:0] count [0:9];
  assign count[0]=0;
  genvar i;
  generate for(i=0;i<9;i=i+1) begin: oracle
    assign count[i+1]=count[i]+(word[50*i+:50]==fingerprint);
  end endgenerate
  assign ok=(present==(count[9]!=0)) && (multiple==(count[9]>1)) &&
            ((count[9]!=1) || ((slot<9) && (selected==fingerprint)));
endmodule

module prove_hash(input wire [127:0] key, output wire ok);
  wire [127:0] value,legacy_value,legacy_right_value;
  wire [13:0] right,legacy_left,legacy_right;
  hw128_hash_terminal new_left(key,value);
  hw128_hash_right new_right(key,right);
  p2_hash_left old_left(key,legacy_value,legacy_left);
  p2_hash_right old_right(key,legacy_right_value,legacy_right);
  assign ok=(value==legacy_value) && (value[13:0]==legacy_left) && (right==legacy_right);
endmodule

// Abstract control proof. Semantic datapath observations are cut to any values.
// This proves resource/handshake bounds; it is not a full-memory semantic proof.
module prove_controller(input wire clk,reset,cmd_valid,cmd_insert,rsp_ready,
  input wire [127:0] cmd_key,main_rdata,
  input wire [511:0] aux_l_rdata,aux_r_rdata, output wire ok);
  wire cmd_ready,rsp_valid,main_read,main_write;
  wire aux_l_read,aux_r_read,aux_l_write,aux_r_write,cam_search,cam_write;
  wire [3:0] rsp_status;
  huawei128_core dut(.clk(clk),.reset(reset),.cmd_valid(cmd_valid),
    .cmd_insert(cmd_insert),.cmd_key(cmd_key),.cmd_ready(cmd_ready),
    .rsp_valid(rsp_valid),.rsp_ready(rsp_ready),.rsp_status(rsp_status),
    .main_read(main_read),.main_write(main_write),.main_rdata(main_rdata),
    .aux_l_read(aux_l_read),.aux_r_read(aux_r_read),
    .aux_l_write(aux_l_write),.aux_r_write(aux_r_write),
    .aux_l_rdata(aux_l_rdata),.aux_r_rdata(aux_r_rdata),
    .cam_search(cam_search),.cam_write(cam_write));
  reg active;
  reg [1:0] mr,mw,aw,cs,cw;
  reg [2:0] ar;
  reg [3:0] age;
  reg held;
  reg [3:0] held_status;
  wire accepted=cmd_valid & cmd_ready;
  always @(posedge clk) begin
    if (reset) begin
      active<=0;mr<=0;mw<=0;ar<=0;aw<=0;cs<=0;cw<=0;age<=0;
      held<=0;held_status<=0;
    end else begin
      if (accepted) begin
        active<=1;mr<=0;mw<=0;ar<=0;aw<=0;cs<=0;cw<=0;age<=1;
      end else if (active) begin
        mr<=mr+main_read;mw<=mw+main_write;
        ar<=ar+{2'b0,aux_l_read}+{2'b0,aux_r_read};
        aw<=aw+aux_l_write+aux_r_write;cs<=cs+cam_search;cw<=cw+cam_write;
        if (rsp_valid) active<=0;
        else age<=age+4'd1;
      end
      held<=rsp_valid & ~rsp_ready;
      held_status<=rsp_status;
    end
  end
  wire bounds=(mr<=1)&(mw<=1)&(ar<=2)&(aw<=1)&(cs<=1)&(cw<=1);
  wire quiet=~(main_read|main_write|aux_l_read|aux_r_read|
               aux_l_write|aux_r_write|cam_search|cam_write);
  assign ok=(!active || (bounds && age<=8 && (!rsp_valid || cs==1))) &&
            (!rsp_valid || quiet) && (!held || (rsp_valid && rsp_status==held_status)) &&
            !(main_read && main_write);
endmodule
