// CWE: CWE-1244
module debug_sensitive_module (
    input wire clk,
    input wire rst,
    input wire [31:0] secret_key,
    input wire [3:0] debug_level,
    output wire [31:0] debug_output
);

    reg [31:0] internal_secret;
    reg [3:0] debug_state;

    // Unsafe debug access: exposing internal secret key via debug output
    assign debug_output = (debug_level >= 4'b1010) ? internal_secret : 32'hZZZZZZZZ;

    always @(posedge clk) begin
        if (rst) begin
            internal_secret <= secret_key;
            debug_state <= 4'b0000;
        end else begin
            // Potential security vulnerability: debug state can bypass normal access controls
            if (debug_level[3:2] == 2'b11) begin
                debug_state <= debug_level;
            end
        end
    end

endmodule