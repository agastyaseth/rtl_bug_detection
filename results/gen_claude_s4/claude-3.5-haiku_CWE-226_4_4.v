// CWE: CWE-226
module sensitive_reuse_module (
    input wire clk,
    input wire rst,
    input wire [31:0] secret_key,
    input wire [7:0] data_in,
    output reg [31:0] encrypted_data
);

    reg [31:0] internal_buffer;
    reg [3:0] use_counter;

    always @(posedge clk) begin
        if (rst) begin
            internal_buffer <= 32'h0;
            encrypted_data <= 32'h0;
            use_counter <= 4'h0;
        end else begin
            // Sensitive information remains in buffer after multiple uses
            if (use_counter < 4'd5) begin
                internal_buffer <= secret_key ^ {24'h0, data_in};
                encrypted_data <= internal_buffer;
                use_counter <= use_counter + 1'b1;
            end
        end
    end

endmodule