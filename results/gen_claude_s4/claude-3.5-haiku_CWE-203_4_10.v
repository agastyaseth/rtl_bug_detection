// CWE: CWE-203
module timing_sensitive_auth (
    input wire clk,
    input wire reset,
    input wire [7:0] password,
    input wire [7:0] stored_hash,
    output reg auth_success
);

    reg [3:0] compare_counter;
    reg [7:0] current_compare_bit;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            auth_success <= 1'b0;
            compare_counter <= 4'd0;
            current_compare_bit <= 8'b0;
        end else begin
            // Timing-sensitive comparison that reveals information through timing
            if (password[compare_counter] == stored_hash[compare_counter]) begin
                // Introduce a small delay only when bits match
                #1 current_compare_bit <= password[compare_counter];
                compare_counter <= compare_counter + 1'b1;
            end else begin
                // Immediate mismatch when bits differ
                auth_success <= 1'b0;
                compare_counter <= 4'd0;
            end

            // Vulnerable observable discrepancy in authentication timing
            if (compare_counter == 4'd8) begin
                auth_success <= 1'b1;
            end
        end
    end

endmodule