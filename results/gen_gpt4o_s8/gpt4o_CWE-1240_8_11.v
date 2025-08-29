// CWE: CWE-1240
module weak_rng(
    input wire clk,
    input wire rst,
    input wire [31:0] seed,
    output reg [31:0] random_number
);

reg [31:0] lfsr;
reg [31:0] lfsr_next;

always @(posedge clk or posedge rst) begin
    if (rst) begin
        lfsr <= seed;
    end else begin
        lfsr <= lfsr_next;
    end
end

always @* begin
    // Linear Feedback Shift Register (LFSR) with a simple tap configuration
    lfsr_next = {lfsr[30:0], lfsr[31] ^ lfsr[28] ^ lfsr[25] ^ lfsr[24]};
    random_number = lfsr_next; // Directly using LFSR output as random number
end

endmodule