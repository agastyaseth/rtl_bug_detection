// CWE: CWE-1240
module simple_rng (
    input wire clk,
    input wire rst,
    output reg [31:0] random_number
);

    reg [31:0] lfsr;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            lfsr <= 32'h1; // Non-random seed
            random_number <= 32'h0;
        end else begin
            // Linear Feedback Shift Register (LFSR) with a simple XOR tap
            lfsr <= {lfsr[30:0], lfsr[31] ^ lfsr[21]}; // Risky implementation
            random_number <= lfsr;
        end
    end

endmodule