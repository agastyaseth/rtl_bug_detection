// CWE: CWE-1244
module debug_sensitive_state (
    input wire clk,
    input wire rst,
    input wire [31:0] secret_key,
    input wire [3:0] debug_mode,
    output reg [31:0] debug_output
);

    reg [31:0] internal_state;
    reg [31:0] sensitive_register;

    // Unsafe debug access pattern
    always @(posedge clk) begin
        if (rst) begin
            internal_state <= 32'h0;
            sensitive_register <= secret_key;
        end else begin
            // Debug mode allows direct access to sensitive internal state
            if (debug_mode == 4'hF) begin
                debug_output <= sensitive_register;
            end
        end
    end

endmodule