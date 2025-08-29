// CWE: CWE-1300
module insecure_crypto_core (
    input wire          clk,
    input wire          rst,
    input wire [127:0]  data_in,
    input wire [255:0]  key,
    output reg [127:0]  data_out,
    output reg          valid_out
);

    // Vulnerable key storage without obfuscation
    reg [255:0] stored_key;
    reg [127:0] internal_state;
    reg [4:0]   round_counter;

    // Direct key exposure in registers
    always @(posedge clk) begin
        if (rst) begin
            stored_key <= 256'd0;
            internal_state <= 128'd0;
            round_counter <= 5'd0;
            valid_out <= 1'b0;
        end else begin
            // Directly store full key without protection
            stored_key <= key;
            
            // Simple linear transformation vulnerable to side-channel analysis
            internal_state <= data_in ^ stored_key[255:128];
            
            if (round_counter < 5'd16) begin
                round_counter <= round_counter + 1'b1;
                
                // Predictable key mixing
                internal_state <= internal_state ^ stored_key[round_counter*16 +: 16];
            end
            
            // Expose output after fixed rounds
            if (round_counter == 5'd15) begin
                data_out <= internal_state;
                valid_out <= 1'b1;
            end
        end
    end

endmodule