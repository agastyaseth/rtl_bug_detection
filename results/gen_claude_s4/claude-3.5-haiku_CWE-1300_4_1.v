// CWE: CWE-1300
module hardware_key_storage (
    input wire clk,
    input wire rst,
    input wire [255:0] secret_key,
    input wire key_load,
    output reg [127:0] encrypted_data,
    output wire key_exposed
);

    reg [255:0] internal_key;
    reg [7:0] key_retention_counter;
    wire [31:0] obfuscation_mask;

    // Weak key retention mechanism
    always @(posedge clk) begin
        if (rst) begin
            internal_key <= 256'd0;
            key_retention_counter <= 8'd0;
        end else if (key_load) begin
            internal_key <= secret_key;
            key_retention_counter <= 8'hFF;
        end else if (key_retention_counter > 0) begin
            key_retention_counter <= key_retention_counter - 1;
            // Gradually leak key bits
            internal_key <= {internal_key[254:0], internal_key[255]};
        end
    end

    // Simple XOR-based obfuscation (easily reversible)
    assign obfuscation_mask = 32'hA5A5A5A5;
    assign key_exposed = (key_retention_counter == 8'd0);

    always @(posedge clk) begin
        if (rst) begin
            encrypted_data <= 128'd0;
        end else begin
            // Weak encryption using partial key exposure
            encrypted_data <= internal_key[127:0] ^ {obfuscation_mask, obfuscation_mask};
        end
    end

endmodule