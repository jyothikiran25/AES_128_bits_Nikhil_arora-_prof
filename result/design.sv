// Code your design here
`timescale 1ns/1ps
// -----------------------------------------------------------------------------
// aes128_enc.sv
//
// Iterative AES-128 encryption block (NIST FIPS-197), one round per cycle.
//
//   * Input : 128-bit plaintext (data_in) and 128-bit key (key_in).
//   * Key   : key_valid = 1 -> key_in is used.
//             key_valid = 0 -> no key supplied: the built-in DEFAULT_KEY is
//             used and default_key_used flags the result.
//   * Output: 256-bit result data_out = {128'h0, ciphertext}. The upper half
//             is reserved and always 0
//
// Handshake (valid/ready on both sides)
//   * A request is transferred at a rising edge with in_valid && in_ready.
//     data_in, key_in and key_valid are sampled only at that edge.
//   * in_ready = 1 only in ST_IDLE (and never while rst_n = 0). It does not
//     depend on in_valid.
//   * The result is offered with out_valid = 1 and held unchanged until it is
//     taken at a rising edge with out_valid && out_ready.
//   * data_out and default_key_used are 0 whenever out_valid = 0.
//
// Timing (request transferred at the end of cycle c0)
//   c1 .. c10  ST_BUSY: round 1..10, round key r computed on the fly
//   c11        ST_DONE: out_valid = 1 (until the host takes the result)
//   Latency: 11 cycles from the transfer edge to the first edge at which the
//   result can be taken. With an always-ready host one request completes
//   every 12 cycles (the next request is accepted in the ST_IDLE cycle after
//   the result was taken).
//
// Security-related behaviour
//   * The AES state and the round key are wiped in the cycle the ciphertext
//     is written to the output register; the output register is wiped when
//     the result is taken. Reset clears everything.
//
// Byte order: byte 0 of key, plaintext and ciphertext is the most significant
// byte ([127:120]), so FIPS-197 / SP 800-38A hex strings can be written
// directly as 'h literals. The AES state is filled column by column:
// byte i -> row i % 4, column i / 4; column c is the word [127-32c -: 32]
// with row 0 in its top byte.
//
// Reset: rst_n is asynchronous, active low. Its release must be synchronous
// to clk (use a reset synchronizer at integration).
// -----------------------------------------------------------------------------
module aes128_enc #(
  // Key used when key_valid = 0. The default is the public FIPS-197
  // Appendix B / SP 800-38A example key, so the behaviour can be checked
  // against published vectors. Override it (e.g. from OTP/fuses) for real use.
  parameter logic [127:0] DEFAULT_KEY = 128'h2b7e151628aed2a6abf7158809cf4f3c
) (
  input  logic         clk,
  input  logic         rst_n,

  // Input channel
  input  logic         in_valid,
  output logic         in_ready,
  input  logic [127:0] data_in,          // plaintext block
  input  logic [127:0] key_in,           // cipher key (used if key_valid = 1)
  input  logic         key_valid,        // 0: use DEFAULT_KEY

  // Output channel
  output logic         out_valid,
  input  logic         out_ready,
  output logic [255:0] data_out,         // {128'h0, ciphertext}
  output logic         default_key_used, // qualifies data_out

  // Status
  output logic         busy              // rounds in progress
);

  // ---------------------------------------------------------------------------
  // AES building blocks
  // ---------------------------------------------------------------------------

  // S-box (FIPS-197 Figure 7), generated from its definition: multiplicative
  // inverse in GF(2^8) mod x^8 + x^4 + x^3 + x + 1, then the affine transform.
  localparam logic [7:0] SBOX [0:255] = '{
    8'h63, 8'h7c, 8'h77, 8'h7b, 8'hf2, 8'h6b, 8'h6f, 8'hc5, 8'h30, 8'h01, 8'h67, 8'h2b, 8'hfe, 8'hd7, 8'hab, 8'h76,  // 0x00
    8'hca, 8'h82, 8'hc9, 8'h7d, 8'hfa, 8'h59, 8'h47, 8'hf0, 8'had, 8'hd4, 8'ha2, 8'haf, 8'h9c, 8'ha4, 8'h72, 8'hc0,  // 0x10
    8'hb7, 8'hfd, 8'h93, 8'h26, 8'h36, 8'h3f, 8'hf7, 8'hcc, 8'h34, 8'ha5, 8'he5, 8'hf1, 8'h71, 8'hd8, 8'h31, 8'h15,  // 0x20
    8'h04, 8'hc7, 8'h23, 8'hc3, 8'h18, 8'h96, 8'h05, 8'h9a, 8'h07, 8'h12, 8'h80, 8'he2, 8'heb, 8'h27, 8'hb2, 8'h75,  // 0x30
    8'h09, 8'h83, 8'h2c, 8'h1a, 8'h1b, 8'h6e, 8'h5a, 8'ha0, 8'h52, 8'h3b, 8'hd6, 8'hb3, 8'h29, 8'he3, 8'h2f, 8'h84,  // 0x40
    8'h53, 8'hd1, 8'h00, 8'hed, 8'h20, 8'hfc, 8'hb1, 8'h5b, 8'h6a, 8'hcb, 8'hbe, 8'h39, 8'h4a, 8'h4c, 8'h58, 8'hcf,  // 0x50
    8'hd0, 8'hef, 8'haa, 8'hfb, 8'h43, 8'h4d, 8'h33, 8'h85, 8'h45, 8'hf9, 8'h02, 8'h7f, 8'h50, 8'h3c, 8'h9f, 8'ha8,  // 0x60
    8'h51, 8'ha3, 8'h40, 8'h8f, 8'h92, 8'h9d, 8'h38, 8'hf5, 8'hbc, 8'hb6, 8'hda, 8'h21, 8'h10, 8'hff, 8'hf3, 8'hd2,  // 0x70
    8'hcd, 8'h0c, 8'h13, 8'hec, 8'h5f, 8'h97, 8'h44, 8'h17, 8'hc4, 8'ha7, 8'h7e, 8'h3d, 8'h64, 8'h5d, 8'h19, 8'h73,  // 0x80
    8'h60, 8'h81, 8'h4f, 8'hdc, 8'h22, 8'h2a, 8'h90, 8'h88, 8'h46, 8'hee, 8'hb8, 8'h14, 8'hde, 8'h5e, 8'h0b, 8'hdb,  // 0x90
    8'he0, 8'h32, 8'h3a, 8'h0a, 8'h49, 8'h06, 8'h24, 8'h5c, 8'hc2, 8'hd3, 8'hac, 8'h62, 8'h91, 8'h95, 8'he4, 8'h79,  // 0xa0
    8'he7, 8'hc8, 8'h37, 8'h6d, 8'h8d, 8'hd5, 8'h4e, 8'ha9, 8'h6c, 8'h56, 8'hf4, 8'hea, 8'h65, 8'h7a, 8'hae, 8'h08,  // 0xb0
    8'hba, 8'h78, 8'h25, 8'h2e, 8'h1c, 8'ha6, 8'hb4, 8'hc6, 8'he8, 8'hdd, 8'h74, 8'h1f, 8'h4b, 8'hbd, 8'h8b, 8'h8a,  // 0xc0
    8'h70, 8'h3e, 8'hb5, 8'h66, 8'h48, 8'h03, 8'hf6, 8'h0e, 8'h61, 8'h35, 8'h57, 8'hb9, 8'h86, 8'hc1, 8'h1d, 8'h9e,  // 0xd0
    8'he1, 8'hf8, 8'h98, 8'h11, 8'h69, 8'hd9, 8'h8e, 8'h94, 8'h9b, 8'h1e, 8'h87, 8'he9, 8'hce, 8'h55, 8'h28, 8'hdf,  // 0xe0
    8'h8c, 8'ha1, 8'h89, 8'h0d, 8'hbf, 8'he6, 8'h42, 8'h68, 8'h41, 8'h99, 8'h2d, 8'h0f, 8'hb0, 8'h54, 8'hbb, 8'h16   // 0xf0
  };

  function automatic logic [7:0] sbox(input logic [7:0] x);
    return SBOX[x];
  endfunction

  // Multiplication by {02} in GF(2^8)
  function automatic logic [7:0] xtime(input logic [7:0] x);
    return {x[6:0], 1'b0} ^ (x[7] ? 8'h1b : 8'h00);
  endfunction

  // SubBytes: S-box on all 16 bytes
  function automatic logic [127:0] sub_bytes(input logic [127:0] s);
    logic [127:0] r;
    for (int i = 0; i < 16; i++) r[8*i +: 8] = sbox(s[8*i +: 8]);
    return r;
  endfunction

  // ShiftRows: row r rotated left by r bytes, out[r][c] = in[r][(c + r) % 4]
  function automatic logic [127:0] shift_rows(input logic [127:0] s);
    logic [127:0] r;
    for (int c = 0; c < 4; c++)
      for (int row = 0; row < 4; row++)
        r[127 - 8*(4*c + row) -: 8] = s[127 - 8*(4*((c + row) % 4) + row) -: 8];
    return r;
  endfunction

  // MixColumns on one column {s0, s1, s2, s3} (s0 = row 0 in the top byte)
  function automatic logic [31:0] mix_column(input logic [31:0] w);
    logic [7:0] s0, s1, s2, s3;
    {s0, s1, s2, s3} = w;
    return { xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3,     // 2 3 1 1
             s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3,     // 1 2 3 1
             s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3,     // 1 1 2 3
             xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3) };   // 3 1 1 2
  endfunction

  function automatic logic [127:0] mix_columns(input logic [127:0] s);
    logic [127:0] r;
    for (int c = 0; c < 4; c++) r[127 - 32*c -: 32] = mix_column(s[127 - 32*c -: 32]);
    return r;
  endfunction

  // Round constant Rcon[round] = x^(round-1), rounds 1..10
  function automatic logic [7:0] rcon(input logic [3:0] round);
    case (round)
      4'd1:    return 8'h01;
      4'd2:    return 8'h02;
      4'd3:    return 8'h04;
      4'd4:    return 8'h08;
      4'd5:    return 8'h10;
      4'd6:    return 8'h20;
      4'd7:    return 8'h40;
      4'd8:    return 8'h80;
      4'd9:    return 8'h1b;
      4'd10:   return 8'h36;
      default: return 8'h00;
    endcase
  endfunction

  // Key expansion step: round key r from round key r-1 (FIPS-197 5.2)
  function automatic logic [127:0] next_round_key(input logic [127:0] rk,
                                                  input logic [7:0]   rc);
    logic [31:0] w0, w1, w2, w3, t;
    {w0, w1, w2, w3} = rk;
    // SubWord(RotWord(w3)) ^ {Rcon, 0, 0, 0}
    t  = {sbox(w3[23:16]), sbox(w3[15:8]), sbox(w3[7:0]), sbox(w3[31:24])}
         ^ {rc, 24'h000000};
    w0 = w0 ^ t;
    w1 = w1 ^ w0;
    w2 = w2 ^ w1;
    w3 = w3 ^ w2;
    return {w0, w1, w2, w3};
  endfunction

  // ---------------------------------------------------------------------------
  // Control and datapath
  // ---------------------------------------------------------------------------
  typedef enum logic [1:0] {
    ST_IDLE = 2'b00,   // waiting for a request
    ST_BUSY = 2'b01,   // rounds 1..10
    ST_DONE = 2'b10    // result offered, waiting for out_ready
  } state_t;

  state_t       state_q;
  logic [127:0] st_q;       // AES state
  logic [127:0] rk_q;       // round key of the previous round
  logic [3:0]   round_q;    // round being computed (1..10), 0 when idle
  logic         dk_q;       // the request in flight uses the default key
  logic [127:0] ct_q;       // ciphertext output register
  logic         out_dk_q;   // default-key flag output register

  logic [127:0] key_sel;    // key of a new request
  logic [127:0] rk_next;    // round key of the current round
  logic [127:0] sub_shift;  // ShiftRows(SubBytes(state))
  logic [127:0] round_out;  // state after the current round
  logic         last_round;

  assign key_sel    = key_valid ? key_in : DEFAULT_KEY;
  assign last_round = (round_q == 4'd10);
  assign rk_next    = next_round_key(rk_q, rcon(round_q));
  assign sub_shift  = shift_rows(sub_bytes(st_q));
  // The final round has no MixColumns
  assign round_out  = (last_round ? sub_shift : mix_columns(sub_shift)) ^ rk_next;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state_q  <= ST_IDLE;
      st_q     <= '0;
      rk_q     <= '0;
      round_q  <= '0;
      dk_q     <= 1'b0;
      ct_q     <= '0;
      out_dk_q <= 1'b0;
    end else begin
      unique case (state_q)
        ST_IDLE: begin
          if (in_valid) begin
            // Initial AddRoundKey; round key 0 is the cipher key
            st_q    <= data_in ^ key_sel;
            rk_q    <= key_sel;
            round_q <= 4'd1;
            dk_q    <= !key_valid;
            state_q <= ST_BUSY;
          end
        end

        ST_BUSY: begin
          if (!last_round) begin
            st_q    <= round_out;
            rk_q    <= rk_next;
            round_q <= round_q + 4'd1;
          end else begin
            // Round 10: ciphertext to the output register, wipe the core
            ct_q     <= round_out;
            out_dk_q <= dk_q;
            st_q     <= '0;
            rk_q     <= '0;
            round_q  <= '0;
            dk_q     <= 1'b0;
            state_q  <= ST_DONE;
          end
        end

        ST_DONE: begin
          if (out_ready) begin
            // Result taken: wipe the output register
            ct_q     <= '0;
            out_dk_q <= 1'b0;
            state_q  <= ST_IDLE;
          end
        end

        default: begin
          // Illegal state encoding: wipe everything and return to idle
          state_q  <= ST_IDLE;
          st_q     <= '0;
          rk_q     <= '0;
          round_q  <= '0;
          dk_q     <= 1'b0;
          ct_q     <= '0;
          out_dk_q <= 1'b0;
        end
      endcase
    end
  end

  // ---------------------------------------------------------------------------
  // Outputs
  // ---------------------------------------------------------------------------
  assign in_ready         = (state_q == ST_IDLE) && rst_n;
  assign busy             = (state_q == ST_BUSY);
  assign out_valid        = (state_q == ST_DONE);
  assign data_out         = {128'h0, ct_q};   // ct_q is 0 outside ST_DONE
  assign default_key_used = out_dk_q;         // 0 outside ST_DONE

endmodule
