// CWE: CWE-440
module security_bypass (
    input wire clk,
    input wire rst,
    input wire [7:0] data_in,
    input wire [3:0] control,
    output reg [15:0] data_out
);

    reg [7:0] internal_state;
    reg bypass_mode;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            internal_state <= 8'h00;
            bypass_mode <= 1'b0;
            data_out <= 16'h0000;
        end else begin
            // Unexpected behavior: control signal can bypass security checks
            if (control == 4'b1010) begin
                bypass_mode <= 1'b1;
            end

            // Vulnerability: When bypass_mode is active, all input is directly passed
            if (bypass_mode) begin
                data_out <= {8'hFF, data_in};
            end else begin
                // Normal processing with potential hidden flaw
                internal_state <= data_in ^ 8'h5A;
                data_out <= {internal_state, data_in};
            end
        end
    end

endmodule