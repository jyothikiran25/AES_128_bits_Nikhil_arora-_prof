// Code your testbench here
// or browse Examples
`timescale 1ns/1ps
// -----------------------------------------------------------------------------
// tb_aes128_enc.sv - self-checking testbench for aes128_enc
//
// Tests
//   1  FIPS-197 App. C.1 known answer with a supplied key (key_valid = 1);
//      internal state wiped after the result.
//   2  Default key (key_valid = 0): FIPS-197 App. B vector, and a request
//      whose key_in carries another valid key that must be ignored.
//   3  Back-to-back SP 800-38A F.1.1 ECB-AES128 blocks with an always-ready
//      host, key_valid alternating 1 / 0. The default key equals the
//      SP 800-38A key, so the ciphertext is the same and only
//      default_key_used changes. Checks one request per 12 cycles.
//   4  Output back-pressure: a result is held for 20 cycles while a second
//      request waits; the second request is accepted only after the first
//      result has been taken, and completes correctly.
//   5  Reset in the middle of an encryption: outputs and internal state
//      cleared, no stale result afterwards, next request correct.
//
// Rules checked every cycle by the monitor
//   - data_out[255:128] == 0
//   - data_out == 0 and default_key_used == 0 while out_valid == 0
//   - exactly one of in_ready / busy / out_valid is 1
//   - a result that has not been taken stays on data_out unchanged
//   - every result taken matches the scoreboard: ciphertext,
//     default_key_used and latency (11 cycles); no result without a request
//
// The testbench drives inputs at the falling edge and samples at the rising
// edge (values before the edge), so there are no races with the DUT.
// -----------------------------------------------------------------------------
module tb_aes128_enc;

  localparam logic [127:0] DEFAULT_KEY = 128'h2b7e151628aed2a6abf7158809cf4f3c;
  localparam int  LATENCY    = 11;    // transfer edge -> first edge the result can be taken
  localparam int  INTERVAL   = 12;    // cycles per request, always-ready host
  localparam int  TIMEOUT    = 200;   // cycles allowed for any single wait
  localparam real CLK_PERIOD = 10.0;  // ns (100 MHz)

  // ---------------------------------------------------------------------------
  // DUT
  // ---------------------------------------------------------------------------
  logic         clk       = 1'b0;
  logic         rst_n     = 1'b0;
  logic         in_valid  = 1'b0;
  logic         in_ready;
  logic [127:0] data_in   = '0;
  logic [127:0] key_in    = '0;
  logic         key_valid = 1'b0;
  logic         out_valid;
  logic         out_ready = 1'b0;
  logic [255:0] data_out;
  logic         default_key_used;
  logic         busy;

  aes128_enc #(.DEFAULT_KEY(DEFAULT_KEY)) dut (
    .clk              (clk),
    .rst_n            (rst_n),
    .in_valid         (in_valid),
    .in_ready         (in_ready),
    .data_in          (data_in),
    .key_in           (key_in),
    .key_valid        (key_valid),
    .out_valid        (out_valid),
    .out_ready        (out_ready),
    .data_out         (data_out),
    .default_key_used (default_key_used),
    .busy             (busy)
  );

  always #(CLK_PERIOD / 2.0) clk = ~clk;

  // ---------------------------------------------------------------------------
  // Bookkeeping
  // ---------------------------------------------------------------------------
  int n_checks = 0;
  int n_fail   = 0;
  int n_in     = 0;   // requests transferred
  int n_out    = 0;   // results taken

  function automatic void check(bit ok, string what);
    n_checks++;
    if (!ok) begin
      n_fail++;
      $display("[%t] FAIL: %s", $realtime, what);
    end
  endfunction

  function automatic int cycles(realtime t0, realtime t1);
    return int'((t1 - t0) / CLK_PERIOD);
  endfunction

  // Scoreboard: one item per transferred request, in order. The item keeps
  // key_valid as presented; the expected default_key_used (!kv) is derived
  // where it is compared. (Verilator 5.016 left the upper bits of a negated
  // 1-bit value unmasked when it was passed to the constructor, so a stored
  // "!kv" never compared equal.)
  class exp_item;
    string        name;
    logic [127:0] ct;
    logic         kv;
    realtime      t_in;
    function new(string name, logic [127:0] ct, logic kv, realtime t_in);
      this.name = name;
      this.ct   = ct;
      this.kv   = kv;
      this.t_in = t_in;
    endfunction
  endclass

  exp_item exp_q[$];
  realtime t_take_q[$];   // edges at which results were taken

  // ---------------------------------------------------------------------------
  // Monitor and scoreboard check (rising edge, values before the edge)
  // ---------------------------------------------------------------------------
  logic         prev_hold  = 1'b0;   // result offered but not taken at the previous edge
  logic         prev_valid = 1'b0;
  logic [255:0] prev_data  = '0;
  logic         prev_dk    = 1'b0;
  realtime      t_first_valid;

  always @(posedge clk) begin : monitor
    exp_item e;
    int      lat;
    bit      exp_dk;
    bit      ok;
    if (!rst_n) begin
      prev_hold  <= 1'b0;
      prev_valid <= 1'b0;
    end else begin
      if (in_valid && in_ready) n_in++;

      if (data_out[255:128] !== 128'h0)
        check(0, $sformatf("data_out[255:128] = %h, must be 0", data_out[255:128]));
      if (!out_valid && (data_out !== '0 || default_key_used !== 1'b0))
        check(0, "data_out / default_key_used not 0 while out_valid = 0");
      if (!$onehot({in_ready, busy, out_valid}))
        check(0, $sformatf("in_ready/busy/out_valid = %b, exactly one expected",
                           {in_ready, busy, out_valid}));
      if (prev_hold && !(out_valid && data_out === prev_data && default_key_used === prev_dk))
        check(0, "result changed or withdrawn before it was taken");

      if (out_valid && !prev_valid) t_first_valid = $realtime;

      if (out_valid && out_ready) begin
        n_out++;
        t_take_q.push_back($realtime);
        if (exp_q.size() == 0) begin
          check(0, $sformatf("result %h offered without a request", data_out));
        end else begin
          e      = exp_q.pop_front();
          exp_dk = (e.kv == 1'b0);
          lat    = cycles(e.t_in, t_first_valid);
          ok     = (data_out === {128'h0, e.ct}) && (default_key_used === exp_dk) && (lat == LATENCY);
          check(data_out === {128'h0, e.ct},
                $sformatf("%s: data_out = %h, expected %h", e.name, data_out, {128'h0, e.ct}));
          check(default_key_used === exp_dk,
                $sformatf("%s: default_key_used = %b, expected %b", e.name, default_key_used, exp_dk));
          check(lat == LATENCY,
                $sformatf("%s: latency %0d cycles, expected %0d", e.name, lat, LATENCY));
          $display("[%t] %s  %s: data_out=%h dk=%0b latency=%0d",
                   $realtime, ok ? "PASS" : "FAIL", e.name, data_out, default_key_used, lat);
        end
      end

      prev_hold  <= out_valid && !out_ready;
      prev_valid <= out_valid;
      prev_data  <= data_out;
      prev_dk    <= default_key_used;
    end
  end

  // ---------------------------------------------------------------------------
  // Driver
  // ---------------------------------------------------------------------------
  // Presents one request and returns after it has been transferred (at the
  // falling edge after the transfer, with the inputs back to idle).
  task automatic send(string name, logic [127:0] pt, logic [127:0] key,
                      logic kv, logic [127:0] exp_ct);
    exp_item e;
    bit      ok;
    int      n;
    @(negedge clk);
    in_valid  = 1'b1;
    data_in   = pt;
    key_in    = key;
    key_valid = kv;
    n = 0;
    do begin
      @(posedge clk);
      ok = in_ready;   // value before the edge: transfer if 1
      n++;
    end while (!ok && n < TIMEOUT);
    check(ok, $sformatf("%s: request not accepted within %0d cycles", name, TIMEOUT));
    if (ok) begin
      e = new(name, exp_ct, kv, $realtime);
      exp_q.push_back(e);
    end
    @(negedge clk);
    in_valid  = 1'b0;
    data_in   = '0;
    key_in    = '0;
    key_valid = 1'b0;
  endtask

  // Waits until every transferred request has produced its result
  task automatic wait_all(string name);
    int n = 0;
    while (exp_q.size() != 0 && n < TIMEOUT) begin
      @(negedge clk);
      n++;
    end
    check(exp_q.size() == 0, $sformatf("%s: %0d result(s) missing", name, exp_q.size()));
    exp_q.delete();
    @(negedge clk);
  endtask

  // ---------------------------------------------------------------------------
  // Tests
  // ---------------------------------------------------------------------------
  task automatic test1_known_answer();
    $display("\n---- TEST 1: FIPS-197 C.1 known answer, key supplied ----");
    out_ready = 1'b1;
    send("T1 FIPS-197 C.1",
         128'h00112233445566778899aabbccddeeff,
         128'h000102030405060708090a0b0c0d0e0f, 1'b1,
         128'h69c4e0d86a7b0430d8cdb78070b4c55a);
    wait_all("T1");
    // White box: core state, round key and output register wiped
    check(dut.st_q == '0 && dut.rk_q == '0 && dut.ct_q == '0 && !dut.out_dk_q,
          "T1: internal state not wiped after the result");
    $display("DONE test 1");
  endtask

  task automatic test2_default_key();
    $display("\n---- TEST 2: no key supplied -> default key ----");
    out_ready = 1'b1;
    // key_in carries junk: must be ignored
    send("T2a default key, FIPS-197 B",
         128'h3243f6a8885a308d313198a2e0370734,
         128'hdeadbeef_0badf00d_feedface_c0ffee00, 1'b0,
         128'h3925841d02dc09fbdc118597196a0b32);
    // key_in carries the FIPS-197 C.1 key: the result must use the default
    // key (8df4..), not key_in (69c4..)
    send("T2b default key, key_in ignored",
         128'h00112233445566778899aabbccddeeff,
         128'h000102030405060708090a0b0c0d0e0f, 1'b0,
         128'h8df4e9aac5c7573a27d8d055d6e4d64b);
    wait_all("T2");
    $display("DONE test 2");
  endtask

  task automatic test3_back_to_back();
    $display("\n---- TEST 3: back-to-back SP 800-38A ECB-AES128, key_valid 1/0/1/0 ----");
    out_ready = 1'b1;
    t_take_q.delete();
    send("T3a SP800-38A blk1 key",
         128'h6bc1bee22e409f96e93d7e117393172a, DEFAULT_KEY,  1'b1,
         128'h3ad77bb40d7a3660a89ecaf32466ef97);
    send("T3b SP800-38A blk2 default",
         128'hae2d8a571e03ac9c9eb76fac45af8e51, ~DEFAULT_KEY, 1'b0,
         128'hf5d3d58503b9699de785895a96fdbaaf);
    send("T3c SP800-38A blk3 key",
         128'h30c81c46a35ce411e5fbc1191a0a52ef, DEFAULT_KEY,  1'b1,
         128'h43b1cd7f598ece23881b00e3ed030688);
    send("T3d SP800-38A blk4 default",
         128'hf69f2445df4f9b17ad2b417be66c3710, '1,           1'b0,
         128'h7b0c785e27e8ad3f8223207104725dd4);
    wait_all("T3");
    check(t_take_q.size() == 4, $sformatf("T3: %0d results taken, expected 4", t_take_q.size()));
    for (int i = 1; i < t_take_q.size(); i++)
      check(cycles(t_take_q[i-1], t_take_q[i]) == INTERVAL,
            $sformatf("T3: results %0d and %0d are %0d cycles apart, expected %0d",
                      i - 1, i, cycles(t_take_q[i-1], t_take_q[i]), INTERVAL));
    $display("DONE test 3");
  endtask

  task automatic test4_backpressure();
    int n_in0;
    int n_wait;
    $display("\n---- TEST 4: output back-pressure, second request waits ----");
    out_ready = 1'b0;
    n_in0     = n_in;
    fork
      begin : driver
        send("T4a result held 20 cycles",
             128'hffffffffffffffffffffffffffffffff,
             128'hffffffffffffffffffffffffffffffff, 1'b1,
             128'hbcbf217cb280cf30b2517052193ab979);
        // Presented while the first request is still in progress
        send("T4b request that had to wait",
             128'ha5a5a5a55a5a5a5a0f0f0f0ff0f0f0f0,
             128'hdeadbeefcafef00d0123456789abcdef, 1'b1,
             128'h0ef79f623610e0d8a46cfc4b1aa5f98c);
      end
      begin : host
        n_wait = 0;
        while (!out_valid && n_wait < TIMEOUT) begin
          @(negedge clk);
          n_wait++;
        end
        check(out_valid, "T4: first result not offered");
        repeat (20) begin
          @(negedge clk);
          check(out_valid && data_out === {128'h0, 128'hbcbf217cb280cf30b2517052193ab979},
                "T4: held result lost or changed");
          check(in_valid && !in_ready && n_in == n_in0 + 1,
                "T4: second request accepted before the first result was taken");
        end
        out_ready = 1'b1;   // take the first result; always ready from now on
      end
    join
    wait_all("T4");
    check(n_in == n_in0 + 2, $sformatf("T4: %0d requests transferred, expected 2", n_in - n_in0));
    $display("DONE test 4");
  endtask

  task automatic test5_reset_recovery();
    int  n_out0;
    bit  seen_valid;
    $display("\n---- TEST 5: reset during an encryption, then recovery ----");
    out_ready = 1'b1;
    send("T5a aborted by reset",
         128'h00112233445566778899aabbccddeeff,
         128'h000102030405060708090a0b0c0d0e0f, 1'b1,
         128'h69c4e0d86a7b0430d8cdb78070b4c55a);
    repeat (4) @(negedge clk);
    check(busy && dut.round_q > 4'd1 && dut.round_q < 4'd10,
          $sformatf("T5: not in the middle of the rounds (busy=%b, round=%0d)", busy, dut.round_q));
    $display("[%t] T5: rst_n asserted in round %0d", $realtime, dut.round_q);
    rst_n = 1'b0;
    #1;
    check(!in_ready && !busy && !out_valid && data_out === '0 && !default_key_used,
          "T5: outputs not cleared by reset");
    check(dut.st_q === '0 && dut.rk_q === '0 && dut.round_q === '0 && dut.ct_q === '0,
          "T5: internal state not cleared by reset");
    exp_q.delete();            // the aborted request has no result
    repeat (3) @(negedge clk);
    rst_n = 1'b1;
    // No stale result may appear
    n_out0     = n_out;
    seen_valid = 0;
    repeat (LATENCY + 5) begin
      @(negedge clk);
      if (out_valid || busy) seen_valid = 1;
    end
    check(!seen_valid && n_out == n_out0 && in_ready, "T5: stale activity after reset");
    // Recovery: all-zero key and plaintext
    send("T5b after reset, zero key/data",
         128'h00000000000000000000000000000000,
         128'h00000000000000000000000000000000, 1'b1,
         128'h66e94bd4ef8a2c3b884cfa59ca342b2e);
    wait_all("T5");
    $display("DONE test 5");
  endtask

  // ---------------------------------------------------------------------------
  // Main
  // ---------------------------------------------------------------------------
  initial 
    begin//{

    end//}
  initial
    begin//{
    $display("tb_aes128_enc: AES-128 encryption block, 5 tests, clock %0.1f MHz",
             1000.0 / CLK_PERIOD);

    rst_n = 1'b0;
    repeat (5) @(negedge clk);
    check(!in_ready && !busy && !out_valid && data_out === '0 && !default_key_used,
          "outputs not idle during reset");
    rst_n = 1'b1;
    @(negedge clk);
    check(in_ready && !busy && !out_valid, "not ready after reset");

    test1_known_answer();
    test2_default_key();
    test3_back_to_back();
    test4_backpressure();
    test5_reset_recovery();

    $display("");
    if (n_fail == 0)
      $display("TEST PASSED (%0d checks, %0d requests, %0d results)", n_checks, n_in, n_out);
    else
      $display("TEST FAILED (%0d of %0d checks failed)", n_fail, n_checks);
    $finish;
    end//}

  initial 
    begin//{
      $dumpfile("tb_aes128_enc.vcd");
      $dumpvars(0, tb_aes128_enc);
      #(CLK_PERIOD * 20000);
      $display("TEST FAILED (global timeout)");
      $finish;
    end//}

endmodule
