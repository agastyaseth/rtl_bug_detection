// CWE: CWE-1272
module aes_core(
    input wire clk,
    input wire rst,
    input wire start,
    input wire [127:0] key,
    input wire [127:0] plaintext,
    output wire [127:0] ciphertext,
    output wire ready
);

//----------------------------------------------------------------
// Internal registers and wires
//----------------------------------------------------------------
reg [127:0] state_reg;
reg [127:0] state_new;
reg [127:0] key_reg;
reg [127:0] key_new;
reg [3:0] round_ctr_reg;
reg [3:0] round_ctr_new;
reg ready_reg;
reg ready_new;
reg state_we;
reg key_we;
reg round_ctr_we;
reg ready_we;

//----------------------------------------------------------------
// AES round constants
//----------------------------------------------------------------
parameter AES_ROUNDS = 10;

//----------------------------------------------------------------
// Register update logic
//----------------------------------------------------------------
always @(posedge clk) begin
    if (rst) begin
        state_reg <= 128'h0;
        key_reg <= 128'h0;
        round_ctr_reg <= 4'h0;
        ready_reg <= 1'b0;
    end else begin
        if (state_we)
            state_reg <= state_new;
        if (key_we)
            key_reg <= key_new;
        if (round_ctr_we)
            round_ctr_reg <= round_ctr_new;
        if (ready_we)
            ready_reg <= ready_new;
    end
end

//----------------------------------------------------------------
// AES encryption logic
//----------------------------------------------------------------
always @* begin
    state_new = state_reg;
    key_new = key_reg;
    round_ctr_new = round_ctr_reg;
    ready_new = ready_reg;
    state_we = 0;
    key_we = 0;
    round_ctr_we = 0;
    ready_we = 0;

    if (start) begin
        state_new = plaintext ^ key;
        key_new = key;
        round_ctr_new = 4'h0;
        ready_new = 1'b0;
        state_we = 1;
        key_we = 1;
        round_ctr_we = 1;
        ready_we = 1;
    end else if (round_ctr_reg < AES_ROUNDS) begin
        // Perform AES round (simplified)
        state_new = state_reg ^ key_reg;
        round_ctr_new = round_ctr_reg + 1;
        state_we = 1;
        round_ctr_we = 1;
    end else begin
        ready_new = 1'b1;
        ready_we = 1;
    end
end

//----------------------------------------------------------------
// Output assignments
//----------------------------------------------------------------
assign ciphertext = state_reg;
assign ready = ready_reg;

endmodule