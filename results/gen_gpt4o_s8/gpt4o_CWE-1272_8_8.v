// CWE: CWE-1272
module aes_core(
    input wire clk,
    input wire rst,
    input wire start,
    input wire [127:0] key,
    input wire [127:0] plaintext,
    output wire [127:0] ciphertext,
    output wire done
);

// Internal registers
reg [127:0] state_reg, state_new;
reg [127:0] key_reg, key_new;
reg [3:0] round_reg, round_new;
reg done_reg, done_new;

// Control signals
reg state_we, key_we, round_we, done_we;

// AES round function (simplified)
function [127:0] aes_round(input [127:0] state, input [127:0] round_key);
    begin
        aes_round = state ^ round_key; // Simplified for demonstration
    end
endfunction

// Register update logic
always @(posedge clk or posedge rst) begin
    if (rst) begin
        state_reg <= 128'h0;
        key_reg <= 128'h0;
        round_reg <= 4'h0;
        done_reg <= 1'b0;
    end else begin
        if (state_we) state_reg <= state_new;
        if (key_we) key_reg <= key_new;
        if (round_we) round_reg <= round_new;
        if (done_we) done_reg <= done_new;
    end
end

// AES operation logic
always @* begin
    state_new = state_reg;
    key_new = key_reg;
    round_new = round_reg;
    done_new = done_reg;
    state_we = 0;
    key_we = 0;
    round_we = 0;
    done_we = 0;

    if (start) begin
        state_new = plaintext;
        key_new = key;
        round_new = 4'h0;
        done_new = 1'b0;
        state_we = 1;
        key_we = 1;
        round_we = 1;
        done_we = 1;
    end else if (round_reg < 4'hA) begin
        state_new = aes_round(state_reg, key_reg);
        round_new = round_reg + 1;
        state_we = 1;
        round_we = 1;
    end else begin
        done_new = 1'b1;
        done_we = 1;
    end
end

// Output assignments
assign ciphertext = state_reg;
assign done = done_reg;

endmodule