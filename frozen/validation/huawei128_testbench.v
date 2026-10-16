`timescale 1ns/1ps
module huawei128_testbench;
  reg clk=0;
  always #5 clk=~clk;
  reg reset=1, cmd_valid=0, cmd_insert=0, rsp_ready=0;
  reg [127:0] cmd_key=0;
  wire cmd_ready, rsp_valid;
  wire [3:0] rsp_status;
  wire main_read,main_write,aux_l_read,aux_r_read,aux_l_write,aux_r_write;
  wire [17:0] main_address;
  wire [127:0] main_wdata,main_rdata;
  wire [13:0] aux_l_address,aux_r_address;
  wire [511:0] aux_l_wdata,aux_r_wdata,aux_l_rdata,aux_r_rdata;
  wire cam_search,cam_write;
  wire [9:0] overflow_count;
  wire [31:0] rejected_count,conflict_count;
  huawei128_core dut(clk,reset,cmd_valid,cmd_insert,cmd_key,cmd_ready,
    rsp_valid,rsp_ready,rsp_status,main_read,main_write,main_address,
    main_wdata,main_rdata,aux_l_read,aux_r_read,aux_l_write,aux_r_write,
    aux_l_address,aux_r_address,aux_l_wdata,aux_r_wdata,aux_l_rdata,aux_r_rdata,
    cam_search,cam_write,overflow_count,rejected_count,conflict_count);
  huawei128_memory memory(clk,main_read,main_write,main_address,main_wdata,main_rdata,
    aux_l_read,aux_r_read,aux_l_write,aux_r_write,aux_l_address,aux_r_address,
    aux_l_wdata,aux_r_wdata,aux_l_rdata,aux_r_rdata);

  integer mr,mw,ar,aw,cs,cw;
  integer cycles,latency,max_latency=0, operations=0,resets=0;
  integer status_totals[0:9];
  reg active=0;
  reg boundary_131071=0,boundary_131072=0,boundary_147455=0;
  reg [17:0] last_main_address=0;
  reg [13:0] last_aux_address=0;
  always @(posedge clk) begin
    if (!reset && cmd_valid && cmd_ready) begin
      active=1; mr=0;mw=0;ar=0;aw=0;cs=0;cw=0;latency=0;
    end
    if (active) begin
      latency=latency+1;
      mr=mr+main_read; mw=mw+main_write;
      ar=ar+aux_l_read+aux_r_read; aw=aw+aux_l_write+aux_r_write;
      cs=cs+cam_search; cw=cw+cam_write;
      if (main_read || main_write) begin
        if (main_address >= 147456) $fatal(1,"invalid main address");
        last_main_address=main_address;
        if (main_address==131071) boundary_131071=1;
        if (main_address==131072) boundary_131072=1;
        if (main_address==147455) boundary_147455=1;
      end
      if (aux_l_write) last_aux_address=aux_l_address;
      if (aux_r_write) last_aux_address=aux_r_address;
      if (mr>1 || mw>1 || ar>2 || aw>1 || cs>1 || cw>1)
        $fatal(1,"operation access budget exceeded");

      if (main_write) begin
        if (dut.target_record[0]) begin
          if (main_wdata[63:0] !== dut.main_word[63:0]) $fatal(1,"low half lost");
        end else if (main_wdata[127:64] !== dut.main_word[127:64]) $fatal(1,"high half lost");
      end
      if ((aux_l_write && aux_l_wdata[511:454] !== 58'b0) ||
          (aux_r_write && aux_r_wdata[511:454] !== 58'b0)) $fatal(1,"aux padding nonzero");
      if (main_read && main_write) $fatal(1,"simultaneous main read/write");
    end
    if (rsp_valid && (main_read || main_write || aux_l_read || aux_r_read ||
                      aux_l_write || aux_r_write || cam_search || cam_write))
      $fatal(1,"command after completed response");
  end

  task reset_table;
    begin
      active=0;
      @(negedge clk); reset=1;cmd_valid=0;rsp_ready=0;
      repeat (2) @(posedge clk);
      @(negedge clk);reset=0;
      cycles=0;
      while (!cmd_ready) begin
        @(posedge clk);#1;
        cycles=cycles+1;
        if (cycles>16385) $fatal(1,"initialization exceeded fixed bound");
      end
      if (overflow_count!==0 || rejected_count!==0) $fatal(1,"reset counters");
      resets=resets+1;
    end
  endtask

  integer fd,rc,op,expected,emr,emw,ear,eaw,ecs,ecw,eoverflow,ereject,hold;
  reg [127:0] key;
  reg [3:0] held_status;
  reg [32767:0] vector_path;
  integer report_fd,j;
  reg [32767:0] report_path;
  initial begin
    for(j=0;j<10;j=j+1) status_totals[j]=0;
    if (!$value$plusargs("vectors=%s",vector_path)) $fatal(1,"missing vectors");
    if (!$value$plusargs("report=%s",report_path)) $fatal(1,"missing report path");
    fd=$fopen(vector_path,"r");
    if (!fd) $fatal(1,"cannot open vectors");
    reset_table;
    while (!$feof(fd)) begin
      rc=$fscanf(fd,"%d %h %d %d %d %d %d %d %d %d %d %d\n",
                  op,key,expected,emr,emw,ear,eaw,ecs,ecw,eoverflow,ereject,hold);
      if (rc==12) begin
        if (op==2) reset_table;
        else begin
          @(negedge clk);
          cmd_key=key;cmd_insert=op;cmd_valid=1;rsp_ready=0;
          @(posedge clk);
          if (!cmd_ready) $fatal(1,"unexpected busy controller");
          @(negedge clk);
          cmd_valid=0;
          // Changing the input bus while busy must not change the accepted key.
          cmd_key=key ^ 128'hffffffffffffffffffffffffffffffff;
          cmd_insert=!op;
          cycles=0;
          while (!rsp_valid) begin
            @(posedge clk);#1;
            cycles=cycles+1;
            if (cycles>12) $fatal(1,"operation exceeded fixed response bound");
          end
          if (rsp_status !== expected[3:0])
            $fatal(1,"status mismatch op=%0d key=%h expected=%0d actual=%0d",op,key,expected,rsp_status);
          if (mr!=emr || mw!=emw || ar!=ear || aw!=eaw || cs!=ecs || cw!=ecw)
            $fatal(1,"access trace mismatch key=%h expected=%0d,%0d,%0d,%0d,%0d,%0d actual=%0d,%0d,%0d,%0d,%0d,%0d",key,emr,emw,ear,eaw,ecs,ecw,mr,mw,ar,aw,cs,cw);
          if (overflow_count !== eoverflow[9:0] || rejected_count !== ereject[31:0] ||
              conflict_count !== (eoverflow+ereject)) $fatal(1,"conflict counter mismatch");
          if (latency>max_latency) max_latency=latency;
          held_status=rsp_status;
          repeat (hold) begin
            @(posedge clk);#1;
            if (!rsp_valid || rsp_status!==held_status || cmd_ready)
              $fatal(1,"response changed under backpressure");
          end
          operations=operations+1;status_totals[expected]=status_totals[expected]+1;
          active=0;
          @(negedge clk);rsp_ready=1;
          @(posedge clk);#1;
          @(negedge clk);rsp_ready=0;
          if (!cmd_ready) $fatal(1,"controller did not return to idle");
        end
      end else if (rc!=-1) $fatal(1,"invalid vector row: fields=%0d",rc);
    end
    $fclose(fd);
    report_fd=$fopen(report_path,"w");
    if (!report_fd) $fatal(1,"cannot open report");
    $fdisplay(report_fd,"{\"passed\":true,\"operations\":%0d,\"resets\":%0d,\"maximum_response_cycles\":%0d,\"boundary_131071\":%0d,\"boundary_131072\":%0d,\"boundary_147455\":%0d,\"status_totals\":[%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d]}",operations,resets,max_latency,boundary_131071,boundary_131072,boundary_147455,status_totals[0],status_totals[1],status_totals[2],status_totals[3],status_totals[4],status_totals[5],status_totals[6],status_totals[7],status_totals[8],status_totals[9]);
    $fclose(report_fd);
    $display("PASS operations=%0d resets=%0d maximum_response_cycles=%0d",operations,resets,max_latency);
    $finish;
  end
endmodule
